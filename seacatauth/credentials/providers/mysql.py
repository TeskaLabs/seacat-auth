import logging
from typing import Optional

import asab
import aiomysql
import passlib.hash
import pymysql
import re

from .abc import EditableCredentialsProviderABC

#

L = logging.getLogger(__name__)

#


class MySQLCredentialsService(asab.Service):

	def __init__(self, app, service_name="seacatauth.credentials.mysql"):
		super().__init__(app, service_name)

	def create_provider(self, provider_id, config_section_name):
		return MySQLCredentialsProvider(self.App, provider_id, config_section_name)


class MySQLCredentialsProvider(EditableCredentialsProviderABC):
	# TODO: Use bind variables (https://legacy.python.org/dev/peps/pep-0249/#paramstyle)

	Type = "mysql"

	ConfigDefaults = {
		"editable": "no",
		"host": "localhost",
		"port": "3306",
		"database": "auth",
		"table": "users",
		"user": "root",
		"password": "",
		"data_fields": ""
	}


	def __init__(self, app, provider_id, config_section_name):
		super().__init__(provider_id, config_section_name)
		self.Editable = self.Config.getboolean("editable")
		self.ConnectionParams = {
			"host": self.Config.get("host"),
			"port": self.Config.getint("port"),
			"db": self.Config.get("database"),
			"user": self.Config.get("user"),
		}
		password = self.Config.get("password")
		if len(password) > 0:
			self.ConnectionParams["password"] = password

		self.ListQuery = self.Config.get("list")
		assert self.ListQuery, "MySQL credentials: 'list' query must be specified"
		self.GetQuery = self.Config.get("get")
		assert self.GetQuery, "MySQL credentials: 'get' query must be specified"
		self.LocateQuery = self.Config.get("locate")
		assert self.LocateQuery, "MySQL credentials: 'locate' query must be specified"

		if self.Editable:
			self.CreateQuery = self.Config.get("create")
			assert self.CreateQuery, "MySQL credentials: 'create' query must be specified"
			self.UpdateQuery = self.Config.get("update")
			assert self.UpdateQuery, "MySQL credentials: 'update' query must be specified"
			self.DeleteQuery = self.Config.get("delete")
			assert self.DeleteQuery, "MySQL credentials: 'delete' query must be specified"

		self.IdField = "_id"
		self.PasswordField = "__password"

		data_fields = self.Config.get("data_fields")
		if len(data_fields) > 0:
			self.DataFields = data_fields.split(" ")
		else:
			self.DataFields = None


	async def create(self, credentials: dict) -> Optional[str]:
		if not self.Editable:
			raise ValueError("Provider '{}:{}' is read-only.".format(self.Type, self.ProviderID))

		# Set unspecified parameters to None
		for param in re.findall(r"[^%]%\((.+?)\)", self.CreateQuery) or []:
			if param not in credentials:
				credentials[param] = None

		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				await cursor.execute(self.CreateQuery, credentials)
				await cursor.execute("SELECT LAST_INSERT_ID();")
				obj_id = await cursor.fetchone()
			try:
				await connection.commit()
			except pymysql.err.IntegrityError as e:
				raise ValueError("Cannot create credentials: {}".format(e)) from e

		credentials_id = "{}{}".format(self.Prefix, obj_id.get("LAST_INSERT_ID()"))
		L.log(asab.LOG_NOTICE, "Credentials created", struct_data={
			"provider_id": self.ProviderID,
			"cid": credentials_id
		})
		return credentials_id


	async def update(self, credentials_id, update: dict) -> Optional[str]:
		if not self.Editable:
			raise ValueError("Provider '{}:{}' is read-only.".format(self.Type, self.ProviderID))

		mysql_id = credentials_id[len(self.Prefix):]
		updated_fields = list(update.keys())

		current_credentials = await self.get(credentials_id, include=[self.PasswordField])
		new_credentials = {}
		expected_fields = frozenset(re.findall(r"[^%]%\((.+?)\)", self.UpdateQuery) or [])

		# Set unspecified parameters to their current value
		for field in expected_fields:
			value = update.pop(field, None)
			if value not in frozenset(["", None]):
				new_credentials[field] = value
			else:
				new_credentials[field] = current_credentials.get(field)

		value = update.pop("password", None)
		if value is not None:
			new_credentials["__password"] = passlib.hash.bcrypt.hash(value.encode("utf-8"))

		value = update.pop("enforce_factors", None)
		if value is not None:
			# TODO: Implement factor enforcement
			L.warning("MySQL: Cannot set field 'enforce_factors'")

		new_credentials[self.IdField] = mysql_id

		if len(update) != 0:
			raise KeyError("Some credentials fields cannot be updated: {}".format(", ".join(update.keys())))

		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				await cursor.execute(self.UpdateQuery, new_credentials)
			try:
				await connection.commit()
			except pymysql.err.IntegrityError as e:
				raise ValueError("Cannot update credentials: {}".format(e)) from e

		L.log(asab.LOG_NOTICE, "Credentials updated", struct_data={
			"provider_id": self.ProviderID,
			"cid": credentials_id,
			"fields": updated_fields
		})


	async def delete(self, credentials_id) -> Optional[str]:
		if not self.Editable:
			raise ValueError("Provider '{}:{}' is read-only.".format(self.Type, self.ProviderID))

		mysql_id = credentials_id[len(self.Prefix):]
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				await cursor.execute(self.DeleteQuery, {"_id": mysql_id})
			try:
				await connection.commit()
			except pymysql.err.IntegrityError as e:
				raise ValueError("Cannot delete credentials: {}".format(e)) from e

		L.log(asab.LOG_NOTICE, "Credentials deleted", struct_data={
			"provider_id": self.ProviderID,
			"cid": credentials_id
		})
		return "OK"


	async def locate(self, ident: str, ident_fields: dict = None) -> Optional[str]:
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				await cursor.execute(self.LocateQuery, {"ident": ident})
				result = await cursor.fetchone()
		if result is None:
			return None
		return "{}{}".format(self.Prefix, result[self.IdField])


	async def get_by(self, key: str, value) -> Optional[dict]:
		raise NotImplementedError()


	async def get(self, credentials_id, include=None) -> Optional[dict]:
		mysql_id = credentials_id[len(self.Prefix):]
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				await cursor.execute(self.GetQuery, {"_id": mysql_id})
				result = await cursor.fetchone()
		if result is None:
			raise KeyError(credentials_id)
		result = self._nomalize_credentials(result, include)
		return result


	async def count(self, filtr=None) -> int:
		# TODO: Filtering
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor() as cursor:
				return await cursor.execute(self.ListQuery)


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
				normalized[field] = db_obj[field]

		normalized["suspended"] = bool(db_obj.get("suspended"))

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
