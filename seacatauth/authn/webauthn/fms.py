import base64
import json
import logging
import cryptography.hazmat.primitives.serialization
import cryptography.x509
import pymongo.errors
import aiohttp
import jwcrypto.jwt
import jwcrypto.jwk
import asab
import asab.storage
import asyncio


L = logging.getLogger(__name__)


class FIDOMetadataService(asab.Service):
	"""
	Service responsible for fetching and storing FIDO metadata from FIDO Alliance Metadata Service (MDS).
	"""
	FidoMetadataServiceCollection = "fms"
	CollectionMetadataCollection = "_meta"


	def __init__(self, app, service_name="seacatauth.FIDOMetadataService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.TaskService = app.get_service("asab.TaskService")

		self.FidoMetadataServiceUrl = asab.Config.get("seacatauth:webauthn", "metadata_service_url")
		if self.FidoMetadataServiceUrl in ("", "DISABLED"):
			raise ValueError("Cannot initialize FIDO Metadata Service: metadata_service_url is not set or disabled.")

		self._update_lock = asyncio.Lock()

		self.TaskService.schedule(self._update_fido_metadata())
		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


	async def _on_housekeeping(self, event_name):
		self.TaskService.schedule(self._update_fido_metadata())


	async def _get_last_fido_mds_etag(self) -> str | None:
		coll = await self.StorageService.collection(self.CollectionMetadataCollection)
		coll_metadata = await coll.find_one(self.FidoMetadataServiceCollection)
		if coll_metadata is not None:
			return coll_metadata.get("source_etag")
		else:
			return None


	async def _update_fido_metadata(self):
		"""
		Download and decode FIDO metadata from FIDO Alliance Metadata Service (MDS) and prepare a lookup dictionary.
		"""
		if self._update_lock.locked():
			L.debug("FIDO metadata load is already in progress, skipping this invocation.")
			return
		async with self._update_lock:
			coll = await self.StorageService.collection(self.FidoMetadataServiceCollection)
			result = await coll.find_one({}, {"_id": 1})
			storage_empty = result is None

			new_etag = None
			if self.FidoMetadataServiceUrl.startswith("https://") or self.FidoMetadataServiceUrl.startswith("http://"):
				headers = {}
				if not storage_empty and (last_etag := await self._get_last_fido_mds_etag()):
					headers["If-None-Match"] = last_etag
					L.debug("Fetching FIDO metadata from MDS with ETag: {}".format(last_etag), struct_data={
						"etag": last_etag,
					})

				try:
					async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
						async with session.get(self.FidoMetadataServiceUrl, headers=headers) as resp:
							if resp.status == 304:
								L.debug(
									"FIDO Metadata Service responded with 304, skipping reload.",
									struct_data={"etag": resp.headers.get("ETag")}
								)
								return
							elif resp.status == 200:
								jwt = await resp.text()
								new_etag = resp.headers.get("ETag")
							else:
								text = await resp.text()
								L.info(
									"FIDO Metadata Service responded with error:\n{!r}.".format(text[:1000]),
									struct_data={"status": resp.status}
								)
								return
				except (TimeoutError, ConnectionError, aiohttp.ClientConnectionError) as e:
					L.info("FIDO Metadata Service is unreachable ({}: {}).".format(e.__class__.__name__, e))
					return

			else:
				# Load from local file
				with open(self.FidoMetadataServiceUrl) as f:
					jwt = f.read()

			try:
				jwt = jwcrypto.jwt.JWT(jwt=jwt)
				cert_chain = jwt.token.jose_header.get("x5c")
				if not cert_chain:
					L.error("FIDO Metadata Service JWT is missing x5c header, cannot validate signature.")
					return
				leaf_cert = cryptography.x509.load_der_x509_certificate(base64.b64decode(cert_chain[0]))
				public_key = leaf_cert.public_key()
				public_key = public_key.public_bytes(
					cryptography.hazmat.primitives.serialization.Encoding.PEM,
					cryptography.hazmat.primitives.serialization.PublicFormat.PKCS1)
				public_key = jwcrypto.jwk.JWK.from_pem(public_key)
				jwt.validate(public_key)
				entries = json.loads(jwt.claims)["entries"]
			except Exception as e:
				L.error("Failed to decode FIDO Metadata Service JWT: {}".format(e))
				return

			# FIDO2 authenticators are identified with AAGUID
			# Other identifiers (AAID, AKI) are not supported at the moment.
			for entry in entries:
				if "aaguid" not in entry:
					continue
				aaguid = bytes.fromhex(entry["aaguid"].replace("-", ""))
				metadata = entry.get("metadataStatement")
				metadata["_id"] = aaguid

			collection = await self.StorageService.collection(self.FidoMetadataServiceCollection)
			client = self.StorageService.Client
			n_inserted = 0
			try:
				async with await client.start_session() as session:
					async with session.start_transaction():
						await collection.delete_many({}, session=session)
						for entry in entries:
							if "aaguid" not in entry:
								continue
							aaguid = bytes.fromhex(entry["aaguid"].replace("-", ""))
							metadata = entry.get("metadataStatement")
							if not metadata:
								continue
							metadata["_id"] = aaguid
							await collection.insert_one(metadata, session=session)
							n_inserted += 1
						if new_etag is not None:
							metadata_coll = await self.StorageService.collection(self.CollectionMetadataCollection)
							await metadata_coll.update_one(
								{"_id": self.FidoMetadataServiceCollection},
								{"$set": {"source_etag": new_etag}},
								upsert=True,
								session=session,
							)
			except pymongo.errors.OperationFailure as e:
				if e.details.get("codeName") == "WriteConflict":
					L.debug(
						"Write conflict while updating FIDO metadata, likely a concurrent update by another app instance."
					)
				else:
					L.error("Failed to update FIDO metadata in storage: {}".format(e))
				return

			L.debug("FIDO metadata fetched and stored.", struct_data={"n_inserted": n_inserted, "etag": new_etag})


	async def get_authenticator_metadata(self, verified_registration) -> dict | None:
		try:
			aaguid = bytes.fromhex(verified_registration.aaguid.replace("-", ""))
		except ValueError:
			L.error("Invalid AAGUID format in registration: {}".format(verified_registration.aaguid))
			return None

		if aaguid == bytes(16):
			# Authenticators with other identifiers than AAGUID are not supported
			metadata = None
		else:
			coll = await self.StorageService.collection(self.FidoMetadataServiceCollection)
			metadata = await coll.find_one(aaguid)
		return metadata
