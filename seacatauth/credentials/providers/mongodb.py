import base64
import hashlib
import logging
import re
from typing import Optional

from passlib.hash import bcrypt

import asab
import asab.storage.mongodb
import asab.storage.exceptions

import bson
import bson.errors

import pymongo
import pymongo.errors

from .abc import EditableCredentialsProviderABC
from ...session import SessionAdapter

#

L = logging.getLogger(__name__)

#


class MongoDBCredentialsService(asab.Service):

	def __init__(self, app, service_name='seacatauth.credentials.mongodb'):
		super().__init__(app, service_name)

	def create_provider(self, provider_id, config_section_name):
		# TODO: Check bcrypt.get_backend() - see https://passlib.readthedocs.io/en/stable/lib/passlib.hash.bcrypt.html#index-0
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
		"tenants": "no",
	}


	def __init__(self, app, provider_id, config_section_name):
		super().__init__(provider_id, config_section_name)
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.MongoDBStorageService = asab.storage.mongodb.StorageService(
			app,
			"seacatauth.credentials.{}.{}.storage".format(self.Type, self.ProviderID),
			config_section_name=config_section_name
		)
		self.CredentialsCollection = self.Config["credentials_collection"]

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

		# Add indexing by active external login providers
		ext_provider_svc = self.SessionService.App.get_service("seacatauth.ExternalLoginService")
		for provider_type in ext_provider_svc.Providers:
			sub_field_name = "external_login.{}".format(provider_type)
			try:
				await coll.create_index(
					[
						(sub_field_name, pymongo.ASCENDING),
					],
					unique=True,
					partialFilterExpression={
						sub_field_name: {"$exists": True, "$gt": ""}
					}
				)
			except Exception as e:
				L.warning("{}; fix it and restart the app".format(e))


	async def create(self, credentials: dict) -> Optional[str]:
		for attribute in ("username", "email", "phone"):
			value = credentials.get(attribute)
			if value is not None and len(value) > 0:
				obj_id = normalize_username(value)
				break
		else:
			raise ValueError("Cannot determine user ID")

		u = self.MongoDBStorageService.upsertor(self.CredentialsCollection, obj_id)
		for field, value in credentials.items():
			u.set(field, value)

		credentials_id = await u.execute()

		L.log(asab.LOG_NOTICE, "Credentials created", struct_data={
			"provider_id": self.ProviderID,
			"cid": credentials_id
		})

		return "{}{}".format(self.Prefix, credentials_id)


	# TODO: refactor to credentials service
	async def register(self, register_info: dict) -> Optional[str]:

		# credentials
		authorization_bytes = register_info.get('request_authorization', b"")
		if authorization_bytes != b"":
			# validate acess token for existing user
			if not authorization_bytes.startswith(b'Bearer '):
				L.warning("Authorization header parsing failed. Probably wrong token type.")
				return

			access_token = base64.urlsafe_b64decode(authorization_bytes[7:])
			try:
				session = await self.SessionService.get_by(SessionAdapter.FN.OAuth2.AccessToken, access_token)
				credentials_id = session.Credentials.Id
			except (KeyError, AttributeError):
				L.warning("Credentials authorization failed.")
				return
		else:
			# create new user
			credentials = await self._construct_credentials(register_info)
			if credentials is None:
				L.warning("Credentials creation failed.")
				return
			credentials_id = await self.create(credentials)
			if credentials_id is None:
				L.warning("Credentials creation failed.")
				return

		# handle tenants
		if self.Config.getboolean("tenants"):
			tenant_assignment = await self._register_tenants(register_info, credentials_id)
			if tenant_assignment is None:
				return

		return credentials_id


	async def _construct_credentials(self, register_info):
		credentials = {}
		if 'email' in register_info['features']:
			username = register_info["request"].get("email")
		elif 'username' in register_info['features']:
			username = register_info["request"].get("username")
		else:
			return
		if username is None:
			return
		credentials['username'] = username

		password = register_info["request"].get("password")
		if password is None:
			return
		credentials['password'] = password

		return credentials


	async def update(self, credentials_id, update: dict) -> Optional[str]:
		if not credentials_id.startswith(self.Prefix):
			raise KeyError("Credentials '{}' not found".format(credentials_id))

		updated_fields = list(update.keys())

		# Fetch the credentials from Mongo
		credentials = await self.MongoDBStorageService.get(
			self.CredentialsCollection,
			bson.ObjectId(credentials_id[len(self.Prefix):])
		)

		# Prepare the update
		u = self.MongoDBStorageService.upsertor(
			self.CredentialsCollection,
			credentials['_id'],
			version=credentials['_v']
		)

		# Update basic credentials
		for field in ("username", "email", "phone", "data"):
			value = update.pop(field, None)
			if value is not None:
				u.set(field, value)

		# Update password
		v = update.pop("password", None)
		if v is not None:
			u.set("__password", bcrypt.hash(v.encode('utf-8')))

		# Update suspension status
		v = update.pop("suspended", None)
		if v is not None:
			u.set("suspended", v is True)

		# Update TOTP secret
		v = update.pop("__totp", None)
		if v is not None:
			u.set("__totp", v)

		# Update enforced factors
		v = update.pop("enforce_factors", None)
		if v is not None:
			u.set("enforce_factors", v)

		# Iterate through the external_login fields
		ext_login_update = []
		for k, v in update.items():
			if k.startswith("external_login."):
				ext_login_update.append(k)
		for k in ext_login_update:
			v = update.pop(k)
			if v is not None:
				u.set(k, v)

		if len(update) != 0:
			raise KeyError("Unsupported credentials fields: {}".format(", ".join(update.keys())))

		try:
			await u.execute()
			L.log(asab.LOG_NOTICE, "Credentials updated", struct_data={
				"cid": credentials_id,
				"fields": updated_fields,
			})
			result = "OK"
		except asab.storage.exceptions.DuplicateError as e:
			if hasattr(e, "KeyValue") and e.KeyValue is not None:
				L.error("Cannot update credentials: Duplicate key", struct_data={
					"cid": credentials_id,
					"conflict": e.KeyValue
				})
				result = {
					"error": "ALREADY-IN-USE",
					"conflict": e.KeyValue,
				}
			else:
				L.error("Cannot update credentials: Duplicate key", struct_data={
					"cid": credentials_id
				})
				result = {
					"error": "ALREADY-IN-USE"
				}

		return result


	async def delete(self, credentials_id) -> Optional[str]:
		# TODO: Soft-delete by change of the `_id`
		await self.MongoDBStorageService.delete(
			self.CredentialsCollection,
			bson.ObjectId(credentials_id[len(self.Prefix):])
		)
		return "OK"


	async def locate(self, ident: str, ident_fields: dict = None) -> Optional[str]:
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
				fields.append({field: re.compile("^{}$".format(ident), re.IGNORECASE)})

		query = {"$or": fields}
		coll = await self.MongoDBStorageService.collection(self.CredentialsCollection)
		obj = await coll.find_one(query)

		if obj is None:
			return None

		return "{}{}".format(self.Prefix, obj["_id"])

	async def get_by(self, key: str, value) -> Optional[dict]:
		coll = await self.MongoDBStorageService.collection(self.CredentialsCollection)
		obj = await coll.find_one({key: value})
		return obj

	async def get_by_external_login_sub(self, login_provider: str, sub_id: str) -> Optional[dict]:
		key = "external_login.{}".format(login_provider)
		obj = await self.get_by(key, sub_id)
		if obj is None:
			return None
		return self._nomalize_credentials(obj)


	async def get(self, credentials_id, include=None) -> Optional[dict]:
		if not credentials_id.startswith(self.Prefix):
			raise KeyError("Credentials '{}' not found".format(credentials_id))

		# Fetch the credentials from a Mongo
		try:
			return self._nomalize_credentials(
				await self.MongoDBStorageService.get(
					self.CredentialsCollection,
					bson.ObjectId(credentials_id[len(self.Prefix):])
				),
				include
			)
		except bson.errors.InvalidId:
			raise KeyError("Credentials '{}' not found".format(credentials_id))


	def build_filter(self, filtr):
		if filtr is None:
			return {}
		else:
			return {'$expr': {'$gt': [{'$indexOfCP': [{'$toLower': '$username'}, filtr.lower()]}, -1]}}


	async def count(self, filtr=None) -> int:
		coll = await self.MongoDBStorageService.collection(self.CredentialsCollection)
		return await coll.count_documents(filter=self.build_filter(filtr))


	async def search(self, filter: dict = None, sort: dict = None, page: int = 0, limit: int = 0) -> list:
		result = []
		coll = await self.MongoDBStorageService.collection(self.CredentialsCollection)
		cursor = coll.find(filter, skip=page * limit, limit=limit, sort=sort)
		while await cursor.fetch_next:
			result.append(
				self._nomalize_credentials(
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

		async for d in cursor:
			yield self._nomalize_credentials(d)


	def _nomalize_credentials(self, db_obj, include=None):
		obj = {
			'_id': "{}:{}:{}".format(self.Type, self.ProviderID, db_obj['_id']),
			'_type': self.Type,
			'_provider_id': self.ProviderID,
		}
		if include is None:
			include = frozenset()
		for key in db_obj.keys():
			if key.startswith('__') and key not in include:
				#  Don't expose private fields
				continue
			if key in ('_id', '_type', '_provider_id'):
				continue
			obj[key] = db_obj[key]
		return obj


	async def get_login_descriptors(self, credentials_id):
		if not credentials_id.startswith(self.Prefix):
			raise KeyError("Credentials '{}' not found".format(credentials_id))

		# Fetch the credentials from a Mongo
		dbcred = await self.MongoDBStorageService.get(
			self.CredentialsCollection,
			bson.ObjectId(credentials_id[len(self.Prefix):])
		)

		default_factors = []

		# TODO: Improve the method of building descriptors
		if '__password' in dbcred:
			default_factors.append({'id': 'password', 'type': 'password'})


		# TODO: Finish OTP deactivation
		# if '__totp' in dbcred:
		# 	default_factors.append({'id': 'totp', 'type': 'totp'})

		# Example of the next factor
		# if 'yubikey_otp_public_id' in dbcred:
		# 	default_factors.append({'id': 'yubikey', 'type': 'yubikey'})

		# Ensure that there is at least one factor
		if len(default_factors) == 0:
			default_factors.append({'id': 'password', 'type': 'password'})

		default_descriptor = {
			'id': 'default',
			'label': 'Use recommended login.',
			'factors': default_factors,
		}

		descriptors = [default_descriptor]

		# Alternatives
		# TODO: Finish SMS login backend
		if 'phone' in dbcred:
			descriptors.append({
				'id': 'smslogin',
				'label': 'Login by SMS.',
				'hideLoginButton': True,
				'factors': [{'id': 'smslogin', 'type': 'smslogin'}]
			})

		return descriptors


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		if not credentials_id.startswith(self.Prefix):
			return False

		# Fetch the credentials from Mongo
		try:
			dbcred = await self.MongoDBStorageService.get(
				self.CredentialsCollection,
				bson.ObjectId(credentials_id[len(self.Prefix):])
			)
		except KeyError:
			# Should not occur if login prologue happened correctly
			L.error("Authentication failed: Credentials not found", struct_data={"cid": credentials_id})
			return False

		if dbcred.get("suspended") is True:
			# if the user is in suspended state then login no allowed
			L.info("Authentication failed: Credentials suspended", struct_data={"cid": credentials_id})
			return False

		if "__password" in dbcred:
			if authn_password(dbcred, credentials):
				return True
			else:
				L.info("Authentication failed: Password verification failed", struct_data={"cid": credentials_id})
		else:
			# Should not occur if login prologue happened correctly
			L.error("Authentication failed: Credentials contain no password", struct_data={"cid": credentials_id})

		return False


def normalize_username(username) -> bson.ObjectId:
	return bson.ObjectId(hashlib.sha224(username.encode('utf-8')).digest()[:12])


def authn_password(dbcred, credentials):
	# This is here for a cryptoagility, if we migrate to a newer password hashing function,
	# this if block will be extended
	if dbcred['__password'].startswith('$2b$') \
		or dbcred['__password'].startswith('$2a$') \
		or dbcred['__password'].startswith('$2y$'):
		if bcrypt.verify(credentials['password'], dbcred['__password']):
			return True
	else:
		L.warning("Unknown password hash function '{}'".format(dbcred['__password'][:4]))
		return False
