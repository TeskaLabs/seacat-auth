import datetime
import json
import logging
from typing import Optional

import asab
import bson
import passlib.hash
import pymysql
import re
import motor
import motor.motor_asyncio

from .abc import EditableCredentialsProviderABC

#

L = logging.getLogger(__name__)

#


class CustomMongoDBCredentialsService(asab.Service):

	def __init__(self, app, service_name="seacatauth.credentials.xmongodb"):
		super().__init__(app, service_name)

	def create_provider(self, provider_id, config_section_name):
		return CustomMongoDBCredentialsProvider(self.App, provider_id, config_section_name)


class CustomMongoDBCredentialsProvider(EditableCredentialsProviderABC):
	# TODO: Use bind variables (https://legacy.python.org/dev/peps/pep-0249/#paramstyle)

	Type = "xmongodb"

	ConfigDefaults = {
		"editable": "no",
		"mongodb_uri": "mongodb://localhost:27017",
		"database": "test",
		"collection": "users",
		"user": "",
		"password": "",
	}


	def __init__(self, app, provider_id, config_section_name):
		super().__init__(provider_id, config_section_name)
		self.Editable = self.Config.getboolean("editable")
		if self.Editable:
			raise NotImplementedError("Custom MongoDB credentials provider does not support editing")

		self.ConnectionParams = {
			"host": self.Config.get("mongodb_uri"),
		}
		for option in ["username", "password"]:
			value = self.Config.get(option, fallback="")
			if len(value) > 0:
				self.ConnectionParams[option] = value

		self.Client = motor.motor_asyncio.AsyncIOMotorClient(**self.ConnectionParams)
		self.Database = self.Client.get_database(
			self.Config.get("database"),
			codec_options=bson.codec_options.CodecOptions(tz_aware=True, tzinfo=datetime.timezone.utc))
		self.Collection = self.Database.get_collection(self.Config.get("collection"))

		self.ListQuery = self.Config.get("list")
		assert self.ListQuery, "XMongoDB credentials: 'list' query/pipeline must be specified"
		self.GetQuery = self.Config.get("get")
		assert self.GetQuery, "XMongoDB credentials: 'get' query/pipeline must be specified"
		self.LocateQuery = self.Config.get("locate")
		assert self.LocateQuery, "XMongoDB credentials: 'locate' query/pipeline must be specified"

		self.IdField = "_id"
		self.PasswordField = "__password"


	def prepare_query(self, query: str, query_args: dict):
		# Surround strings with double quotes to be JSON-deserializable
		for k, v in query_args.items():
			if isinstance(v, str):
				query_args[k] = '"{}"'.format(v)
		bound_query = query % query_args
		return json.loads(bound_query)


	async def create(self, credentials: dict) -> Optional[str]:
		raise NotImplementedError()


	async def register(self, register_info: dict) -> Optional[str]:
		raise NotImplementedError()


	async def update(self, credentials_id, update: dict) -> Optional[str]:
		raise NotImplementedError()


	async def delete(self, credentials_id) -> Optional[str]:
		raise NotImplementedError()


	async def locate(self, ident: str, ident_fields: dict = None) -> Optional[str]:
		query = self.prepare_query(self.GetQuery, {"ident": ident})
		cursor = self.Collection.aggregate(query)
		try:
			result = await cursor.next()
		except StopIteration:
			return None
		return "{}{}".format(self.Prefix, result[self.IdField])


	async def get_by(self, key: str, value) -> Optional[dict]:
		raise NotImplementedError()


	async def get(self, credentials_id, include=None) -> Optional[dict]:
		mongodb_id = credentials_id[len(self.Prefix):]
		query = self.prepare_query(self.GetQuery, {self.IdField: mongodb_id})
		cursor = self.Collection.aggregate(query)
		try:
			result = await cursor.next()
		except StopIteration:
			raise KeyError(credentials_id)
		result = self._nomalize_credentials(result, include)
		return result


	async def count(self, filtr=None) -> int:
		# TODO: Filtering
		query = self.prepare_query(self.ListQuery, {})
		query.append({"$count": "count"})
		cursor = self.Collection.aggregate(query)
		try:
			result = await cursor.next()
			return result["count"]
		except (StopIteration, KeyError):
			raise RuntimeError("Credential count failed.")


	async def search(self, filter: dict = None, sort: dict = None, page: int = 0, limit: int = -1) -> list:
		# TODO: Filtering
		if limit > 0:
			offset = page * limit
		else:
			offset = 0

		results = []
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				nrows = await cursor.execute(self.ListQuery)
				if nrows == 0:
					return []
				try:
					await cursor.scroll(offset)
				except IndexError:
					L.error("MySQL: Out of range", struct_data={"query": self.ListQuery, "scroll": offset})
					return []
				result = await cursor.fetchone()
				while result is not None:
					results.append(self._nomalize_credentials(result))
					if limit > 0:
						limit -= 1
					if limit == 0:
						break
					result = await cursor.fetchone()
		return result


	async def iterate(self, offset: int = 0, limit: int = -1, filtr: str = None):
		# TODO: Filtering
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				nrows = await cursor.execute(self.ListQuery)
				if nrows == 0:
					return
				try:
					await cursor.scroll(offset)
				except IndexError:
					L.error("MySQL: Out of range", struct_data={"query": self.ListQuery, "scroll": offset})
					return
				result = await cursor.fetchone()
				while result is not None:
					yield self._nomalize_credentials(result)
					if limit > 0:
						limit -= 1
					if limit == 0:
						return
					result = await cursor.fetchone()


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		if not credentials_id.startswith(self.Prefix):
			return False

		# Fetch the credentials from Mongo
		try:
			dbcred = await self.get(credentials_id, include=[self.PasswordField])
		except KeyError:
			# Not my user
			L.error("Authentication failed: Credentials not found", struct_data={"cid": credentials_id})
			return False

		if dbcred.get("suspended") is True:
			# if the user is in suspended state then login no allowed
			L.info("Authentication failed: Credentials suspended", struct_data={"cid": credentials_id})
			return False

		if self.PasswordField in dbcred:
			if self._authenticate_password(dbcred, credentials):
				return True
			else:
				L.info("Authentication failed: Password verification failed", struct_data={"cid": credentials_id})
		else:
			L.error("Authentication failed: Login data contain no password", struct_data={"cid": credentials_id})
		return False


	def _nomalize_credentials(self, db_obj, include=None):
		normalized = {
			'_id': "{}:{}:{}".format(self.Type, self.ProviderID, db_obj[self.IdField]),
			'_type': self.Type,
			'_provider_id': self.ProviderID,
		}

		for field in frozenset(["username", "email", "phone"]):
			if field in db_obj:
				normalized[field] = db_obj.pop(field)

		normalized["suspended"] = bool(db_obj.pop("suspended", False))

		data = {}
		for field in self.DataFields:
			if field in db_obj:
				data[field] = db_obj[field]
		if len(data) > 0:
			normalized["data"] = data

		if include is not None:
			for field in include:
				if field in db_obj:
					normalized[field] = db_obj[field]

		return normalized


	def _authenticate_password(self, dbcred, credentials):
		# This is here for a cryptoagility, if we migrate to a newer password hashing function,
		# this if block will be extended
		if dbcred[self.PasswordField].startswith("$2b$") \
			or dbcred[self.PasswordField].startswith("$2a$") \
			or dbcred[self.PasswordField].startswith("$2y$"):
			if passlib.hash.bcrypt.verify(credentials["password"], dbcred[self.PasswordField]):
				return True
		else:
			L.warning("Unknown password hash function: {}".format(dbcred[self.PasswordField][:4]))
			return False
