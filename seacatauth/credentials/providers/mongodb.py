import hashlib
import logging
import re
import typing
import asab
import asab.storage.mongodb
import asab.storage.exceptions
import asab.exceptions
import bson
import bson.errors
import pymongo
import pymongo.errors

from .abc import EditableCredentialsProviderABC
from ... import generic, exceptions
from ...events import EventTypes


L = logging.getLogger(__name__)


class MongoDBCredentialsService(asab.Service):

	def __init__(self, app, service_name='seacatauth.credentials.mongodb'):
		super().__init__(app, service_name)

	def create_provider(self, provider_id, config_section_name):
		return MongoDBCredentialsProvider(self.App, provider_id, config_section_name)


class MongoDBCredentialsProvider(EditableCredentialsProviderABC):
	"""
	Credentials provider with MongoDB backend.

	Config options:
		credentials_collection: str
		Name of credentials collection.

		registration_features: str
		Whitespace-separated list of features available in credentials self-registration procedure.

		creation_features: str
		Whitespace-separated list of features available in credentials creation procedure.

		ident_fields: str
		Whitespace-separated list of features which are searched by the .locate() method.
		A feature can be spefified with ":ignorecase" modifier (e.g. "username:ignorecase")
		for case-insensitive searching.
	"""

	Type = "mongodb"

	ConfigDefaults = {
		"credentials_collection": "c",
		"registration": "yes",
	}


	def __init__(self, app, provider_id, config_section_name):
		super().__init__(app, provider_id, config_section_name)
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.MongoDBStorageService = asab.storage.mongodb.StorageService(
			app,
			"seacatauth.credentials.{}.{}.storage".format(self.Type, self.ProviderID),
			config_section_name=config_section_name
		)
		self.CredentialsCollection = self.Config["credentials_collection"]
		self.RegistrationEnabled = self.Config.getboolean("registration")

		app.TaskService.schedule(self.initialize())


	async def initialize(self):
		coll = await self.MongoDBStorageService.collection(self.CredentialsCollection)

		# Index all attributes that can be used for locating
		for attribute in ("username", "email", "phone"):
			try:
				await coll.create_index(
					[
						(attribute, pymongo.ASCENDING),
					],
					unique=True,
					partialFilterExpression={
						attribute: {"$exists": True, "$gt": ""}
					}
				)
			except Exception as e:
				L.warning("{}; fix it and restart the app".format(e))

		# Index by registration code
		try:
			await coll.create_index(
				[
					("__registration.code", pymongo.ASCENDING),
				],
				unique=True,
				partialFilterExpression={
					"__registration.code": {"$exists": True, "$gt": ""}
				}
			)
		except Exception as e:
			L.warning("{}; fix it and restart the app".format(e))


	async def create(self, credentials: dict) -> typing.Optional[str]:
		for attribute in ("username", "email", "phone"):
			value = credentials.get(attribute)
			if value is not None and len(value) > 0:
				obj_id = self._create_credential_id(value)
				break
		else:
			raise ValueError("Cannot determine user ID")

		u = self.MongoDBStorageService.upsertor(self.CredentialsCollection, obj_id)

		for field, value in credentials.items():
			u.set(field, value)

		mongodb_id = await u.execute(event_type=EventTypes.CREDENTIALS_CREATED)
		credentials_id = self._format_credentials_id(mongodb_id)

		L.log(asab.LOG_NOTICE, "Credentials created", struct_data={
			"provider_id": self.ProviderID,
			"cid": credentials_id
		})
		return credentials_id


	async def update(self, credentials_id, update: dict) -> typing.Optional[str]:
		try:
			mongodb_id = self._format_object_id(credentials_id)
		except ValueError:
			raise exceptions.CredentialsNotFoundError(credentials_id)

		updated_fields = list(update.keys())

		# Fetch the credentials from Mongo
		credentials = await self.MongoDBStorageService.get(self.CredentialsCollection, mongodb_id)

		# Prepare the update
		u = self.MongoDBStorageService.upsertor(
			self.CredentialsCollection,
			credentials["_id"],
			version=credentials["_v"]
		)

		# Update password
		v = update.pop("password", None)
		if v is not None:
			u.set("__password", generic.argon2_hash(v))

		# Update basic credentials
		for key, value in update.items():
			if key not in ("username", "email", "phone", "suspended", "data", "__totp", "enforce_factors", "__registration"):
				L.warning("Updating unknown field: {}".format(key))
			if value is not None:
				u.set(key, value)
			else:
				u.unset(key)

		try:
			await u.execute(event_type=EventTypes.CREDENTIALS_UPDATED)
			L.log(asab.LOG_NOTICE, "Credentials updated", struct_data={
				"cid": credentials_id,
				"fields": ", ".join(updated_fields or []),
			})
		except asab.storage.exceptions.DuplicateError as e:
			if hasattr(e, "KeyValue") and e.KeyValue is not None:
				key, value = e.KeyValue.popitem()
				raise asab.exceptions.Conflict(key=key, value=value)
			else:
				raise asab.exceptions.Conflict()

		return credentials_id


	async def delete(self, credentials_id) -> typing.Optional[str]:
		# TODO: Soft-delete by change of the `_id`
		# Verify that credentials exists
		await self.get(credentials_id)
		await self.MongoDBStorageService.delete(self.CredentialsCollection, self._format_object_id(credentials_id))
		return credentials_id


	async def locate(self, ident: str, ident_fields: dict = None, login_dict: dict = None) -> typing.Optional[str]:
		"""
		Locate credentials by matching ident string against configured ident fields.
		"""
		if ident_fields is None:
			ident_fields = ["username"]

		fields = []
		for field, mode in ident_fields.items():
			if mode is None:
				fields.append({field: ident})
			if mode == "ignorecase":
				fields.append({field: re.compile("^{}$".format(re.escape(ident)), re.IGNORECASE)})

		query = {"$or": fields}
		coll = await self.MongoDBStorageService.collection(self.CredentialsCollection)
		obj = await coll.find_one(query)

		if obj is None:
			return None

		return self._format_credentials_id(obj["_id"])


	async def get_by(self, key: str, value, include=None) -> typing.Optional[dict]:
		coll = await self.MongoDBStorageService.collection(self.CredentialsCollection)
		obj = await coll.find_one({key: value})
		if obj is None:
			raise KeyError("Found no credentials with {}={}".format(key, repr(value)))
		return self._normalize_credentials(obj, include)


	async def get(self, credentials_id, include=None) -> typing.Optional[dict]:
		try:
			mongodb_id = self._format_object_id(credentials_id)
		except ValueError:
			raise exceptions.CredentialsNotFoundError(credentials_id)

		try:
			db_obj = await self.MongoDBStorageService.get(self.CredentialsCollection, bson.ObjectId(mongodb_id))
		except KeyError:
			raise exceptions.CredentialsNotFoundError(credentials_id)

		return self._normalize_credentials(db_obj, include)


	def build_filter(self, filtr):
		if filtr is None:
			return {}
		else:
			return {"$expr": {"$gt": [{"$indexOfCP": [{"$toLower": "$username"}, filtr.lower()]}, -1]}}


	async def count(self, filtr: str = None) -> int:
		coll = await self.MongoDBStorageService.collection(self.CredentialsCollection)
		if (filtr is None):
			return await coll.estimated_document_count()
		else:
			return await coll.count_documents(filter=self.build_filter(filtr))


	async def search(self, filter: dict = None, sort: dict = None, page: int = 0, limit: int = 0) -> list:
		result = []
		coll = await self.MongoDBStorageService.collection(self.CredentialsCollection)
		cursor = coll.find(filter, skip=page * limit, limit=limit, sort=sort)
		while await cursor.fetch_next:
			result.append(
				self._normalize_credentials(
					cursor.next_object()
				)
			)
		return result


	async def iterate(self, offset: int = 0, limit: int = -1, filtr: str = None):
		coll = await self.MongoDBStorageService.collection(self.CredentialsCollection)
		cursor = coll.find(
			filter=self.build_filter(filtr),
			skip=offset,
		)
		if limit >= 0:
			cursor.limit(limit)

		cursor.sort("username", 1)

		async for d in cursor:
			yield self._normalize_credentials(d)


	def _normalize_credentials(self, db_obj, include=None):
		obj = {
			"_id": self._format_credentials_id(db_obj["_id"]),
			"_type": self.Type,
			"_provider_id": self.ProviderID,
		}
		if include is None:
			include = frozenset()
		for key in db_obj.keys():
			if key.startswith("__") and key not in include:
				#  Don't expose private fields
				continue
			if key in ("_id", "_type", "_provider_id"):
				continue
			obj[key] = db_obj[key]

		if "__registration" in db_obj:
			obj["registered"] = False

		return obj


	async def get_login_descriptors(self, credentials_id):
		dbcred = await self.get(credentials_id, include={"__password"})

		default_factors = []

		# TODO: Improve the method of building descriptors
		if "__password" in dbcred:
			default_factors.append({"id": "password", "type": "password"})

		# Ensure that there is at least one factor
		if len(default_factors) == 0:
			default_factors.append({"id": "password", "type": "password"})

		default_descriptor = {
			"id": "default",
			"label": "Use recommended login.",
			"factors": default_factors,
		}

		descriptors = [default_descriptor]

		# Alternatives
		# TODO: Finish SMS login backend
		if "phone" in dbcred:
			descriptors.append({
				"id": "smslogin",
				"label": "Login by SMS.",
				"hideLoginButton": True,
				"factors": [{"id": "smslogin", "type": "smslogin"}]
			})

		return descriptors


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		try:
			dbcred = await self.get(credentials_id, include={"__password"})
		except KeyError:
			# Should not occur if login prologue happened correctly
			L.error("Authentication failed: Credentials not found.", struct_data={"cid": credentials_id})
			return False

		if dbcred.get("suspended") is True:
			# if the user is in suspended state then login no allowed
			L.info("Authentication failed: Credentials suspended.", struct_data={"cid": credentials_id})
			return False

		password = credentials.get("password")
		if not password:
			L.error("Authentication failed: Login data contain no password.", struct_data={"cid": credentials_id})
			return False

		password_hash = dbcred.get("__password")
		if not password_hash:
			# Should not occur if login prologue happened correctly
			L.error("Authentication failed: User has no password set.", struct_data={"cid": credentials_id})
			return False

		if self._verify_password(password_hash, password):
			return True
		else:
			L.info("Authentication failed: Password verification failed", struct_data={"cid": credentials_id})

		return False


	def _create_credential_id(self, username) -> bson.ObjectId:
		return bson.ObjectId(hashlib.sha224(username.encode("utf-8")).digest()[:12])


	def _format_object_id(self, credentials_id: str) -> bson.ObjectId:
		"""
		Remove provider prefix from credentials ID and convert to BSON object ID.
		"""
		if not credentials_id.startswith(self.Prefix):
			raise ValueError("Credentials ID does not start with {!r} prefix.".format(self.Prefix))

		try:
			mongodb_id = bson.ObjectId(credentials_id[len(self.Prefix):])
		except bson.errors.InvalidId:
			raise ValueError("Invalid credentials ID: {}".format(credentials_id))

		return mongodb_id
