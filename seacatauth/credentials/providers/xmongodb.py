import datetime
import logging
import typing
import asab
import bson
import motor
import motor.motor_asyncio
import bson.json_util

from .abc import CredentialsProviderABC


L = logging.getLogger(__name__)


class XMongoDBCredentialsService(asab.Service):

	def __init__(self, app, service_name="seacatauth.credentials.xmongodb"):
		super().__init__(app, service_name)

	def create_provider(self, provider_id, config_section_name):
		if asab.Config.getboolean(config_section_name, "editable", fallback=False):
			# TODO: Implement editable provider
			raise NotImplementedError("EditableXMongoDBCredentialsProvider")
		else:
			return XMongoDBCredentialsProvider(self.App, provider_id, config_section_name)


class XMongoDBCredentialsProvider(CredentialsProviderABC):
	"""
	Customizable read-only MongoDB provider
	"""

	Type = "xmongodb"

	ConfigDefaults = {
		"mongodb_uri": "mongodb://localhost:27017",
		"database": "test",
		"collection": "users",
		"user": "",
		"password": "",
	}

	def __init__(self, app, provider_id, config_section_name):
		super().__init__(provider_id, config_section_name)

		self.ConnectionParams = {
			"host": self.Config.get("mongodb_uri"),
		}
		for option in ["username", "password"]:
			value = self.Config.get(option, "")
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


	def _prepare_query(self, query: str, query_args: dict):
		# Surround strings with double quotes to be JSON-deserializable
		for k, v in query_args.items():
			if isinstance(v, str):
				query_args[k] = '"{}"'.format(v)
		bound_query = query % query_args
		return bson.json_util.loads(bound_query)


	async def locate(self, ident: str, ident_fields: dict = None, login_dict: dict = None) -> typing.Optional[str]:
		kwargs = {"ident": ident}
		if login_dict is not None:
			kwargs.update(login_dict)
		query = self._prepare_query(self.LocateQuery, kwargs)
		cursor = self.Collection.aggregate(query)
		result = None
		async for obj in cursor:
			result = obj
			break
		if result is None:
			return None
		return "{}{}".format(self.Prefix, result[self.IdField])


	async def get_by(self, key: str, value) -> typing.Optional[dict]:
		raise NotImplementedError()


	async def get(self, credentials_id, include=None) -> typing.Optional[dict]:
		mongodb_id = credentials_id[len(self.Prefix):]
		query = self._prepare_query(self.GetQuery, {self.IdField: mongodb_id})
		cursor = self.Collection.aggregate(query)
		result = None
		async for obj in cursor:
			result = obj
			break
		if result is None:
			raise KeyError(credentials_id)
		result = self._nomalize_credentials(result, include)
		return result


	async def count(self, filtr: str = None) -> typing.Optional[int]:
		# TODO: Filtering
		return await self.Collection.estimated_document_count()


	async def search(self, filter: dict = None, sort: dict = None, page: int = 0, limit: int = -1) -> list:
		# TODO: Filtering
		query = self._prepare_query(self.ListQuery, {})
		if sort is not None:
			query.append({"$sort": sort})
		if page > 0:
			query.append({"$skip": page * limit})
		if limit > -1:
			query.append({"$limit": limit})
		cursor = self.Collection.aggregate(query)
		result = []
		async for obj in cursor:
			result.append(self._nomalize_credentials(obj))
		return result


	async def iterate(self, offset: int = 0, limit: int = -1, filtr: str = None):
		# TODO: Filtering
		query = self._prepare_query(self.ListQuery, {})
		if offset > 0:
			query.append({"$skip": offset})
		if limit > -1:
			query.append({"$limit": limit})
		cursor = self.Collection.aggregate(query)

		async for obj in cursor:
			yield self._nomalize_credentials(obj)


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		if not credentials_id.startswith(self.Prefix):
			return False

		# Fetch the credentials from Mongo
		try:
			dbcred = await self.get(credentials_id, include=[self.PasswordField])
		except KeyError:
			L.error("Authentication failed: Credentials not found.", struct_data={"cid": credentials_id})
			return False

		if dbcred.get("suspended") is True:
			L.info("Authentication failed: Credentials suspended.", struct_data={"cid": credentials_id})
			return False

		password = credentials.get("password")
		if not password:
			L.error("Authentication failed: Login data contain no password.", struct_data={"cid": credentials_id})
			return False

		password_hash = dbcred.get(self.PasswordField)
		if not password_hash:
			# Should not occur if login prologue happened correctly
			L.error("Authentication failed: User has no password set.", struct_data={"cid": credentials_id})
			return False

		if self._verify_password(password_hash, password):
			return True
		else:
			L.info("Authentication failed: Password verification failed", struct_data={"cid": credentials_id})

		return True


	def _nomalize_credentials(self, db_obj, include=None):
		normalized = {
			'_id': "{}:{}:{}".format(self.Type, self.ProviderID, db_obj.pop(self.IdField)),
			'_type': self.Type,
			'_provider_id': self.ProviderID,
		}

		for field in frozenset(["_v", "_c", "_m"]):
			if field in db_obj:
				normalized[field] = db_obj.pop(field)

		for field in frozenset(["username", "email", "phone"]):
			if field in db_obj:
				normalized[field] = db_obj.pop(field)

		normalized["suspended"] = bool(db_obj.pop("suspended", False))

		data = {}
		for k, v in db_obj.items():
			if not k.startswith("_"):
				data[k] = v
		if len(data) > 0:
			normalized["data"] = data

		if include is not None:
			for field in include:
				if field in db_obj:
					normalized[field] = db_obj[field]

		return normalized
