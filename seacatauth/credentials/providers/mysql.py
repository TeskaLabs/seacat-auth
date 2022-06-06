import logging
from typing import Optional

import asab
import aiomysql
import passlib.hash
import pymysql

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
		"field_id": "id",
		"field_username": "username",
		"field_email": "email",
		"field_phone": "phone",
		"field_password": "password",
		"field_suspended": "suspended",
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

		self.Table = self.Config.get("table")

		self.Fields = {
			"username": self.Config.get("field_username"),
			"email": self.Config.get("field_email"),
			"phone": self.Config.get("field_phone"),
			"suspended": self.Config.get("field_suspended"),
		}
		self.IdField = self.Config.get("field_id")
		self.PasswordField = self.Config.get("field_password")

		data_fields = self.Config.get("data_fields")
		if len(data_fields) > 0:
			self.DataFields = data_fields.split(" ")
		else:
			self.DataFields = None


	async def create(self, credentials: dict) -> Optional[str]:
		db_fields = []
		values = []
		for field, db_field in self.Fields.items():
			if field in credentials:
				db_fields.append(db_field)
				values.append(credentials[field])
		query = "INSERT INTO `{table}` ({fields}) VALUES ({values});".format(
			table=self.Table,
			fields=", ".join(db_fields),
			values=", ".join("%s" for _ in values),
		)
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				await cursor.execute(query, values)
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


	async def register(self, register_info: dict) -> Optional[str]:
		raise NotImplementedError()


	async def update(self, credentials_id, update: dict) -> Optional[str]:
		mysql_id = credentials_id[len(self.Prefix):]
		updated_fields = list(update.keys())

		assignments = []

		for field, db_field in self.Fields.items():
			value = update.pop(field, None)
			if value not in frozenset(["", None]):
				assignments.append("`{}` = '{}'".format(db_field, value))

		query = "UPDATE `{table}` SET {assignments} WHERE `{id_field}` = {mysql_id};".format(
			table=self.Table,
			assignments=", ".join(assignments),
			id_field=self.IdField,
			mysql_id=mysql_id,
		)

		if len(update) != 0:
			raise KeyError("Some credentials fields cannot be updated: {}".format(", ".join(update.keys())))

		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				await cursor.execute(query)
			try:
				await connection.commit()
			except pymysql.err.IntegrityError as e:
				raise ValueError("Cannot update credentials: {}".format(e)) from e

		L.log(asab.LOG_NOTICE, "Credentials updated", struct_data={
			"provider_id": self.ProviderID,
			"cid": credentials_id,
			"fields": updated_fields
		})
		return "OK"


	async def delete(self, credentials_id) -> Optional[str]:
		mysql_id = credentials_id[len(self.Prefix):]
		query = "DELETE FROM `{table}` WHERE `{field}` = {value};".format(
			table=self.Table,
			field=self.IdField,
			value=mysql_id,
		)
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				await cursor.execute(query)
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
		if ident_fields is None:
			ident_fields = ["username"]

		conditions = []
		for field, mode in ident_fields.items():
			field = self.Fields[field]
			if mode is None:
				conditions.append("(`{field}` = '{ident}')".format(field=field, ident=ident))
			if mode == "ignorecase":
				conditions.append("(LOWER(`{field}`) = '{ident}')".format(field=field, ident=ident))
		query = "SELECT * FROM `{table}` WHERE {where};".format(
			table=self.Table,
			where=" OR ".join(conditions),
		)
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				await cursor.execute(query)
				result = await cursor.fetchone()
		if result is None:
			return None
		return "{}{}".format(self.Prefix, result[self.IdField])


	async def get_by(self, key: str, value) -> Optional[dict]:
		query = "SELECT * FROM `{table}` WHERE `{field}` = {value};".format(
			table=self.Table,
			field=key,
			value=value,
		)
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				await cursor.execute(query)
				result = await cursor.fetchone()
		if result is None:
			raise KeyError(value)
		result = self._nomalize_credentials(result)
		return result


	async def get_by_external_login_sub(self, login_provider: str, sub_id: str) -> Optional[dict]:
		raise NotImplementedError()


	async def get(self, credentials_id, include=None) -> Optional[dict]:
		mysql_id = credentials_id[len(self.Prefix):]
		query = "SELECT * FROM `{table}` WHERE `{field}` = {value};".format(
			table=self.Table,
			field=self.IdField,
			value=mysql_id,
		)
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				await cursor.execute(query)
				result = await cursor.fetchone()
		if result is None:
			raise KeyError(credentials_id)
		result = self._nomalize_credentials(result, include)
		return result


	async def count(self, filtr=None) -> int:
		if filtr is not None:
			where = "WHERE `{}` = {}".format(self.Fields["username"], filtr)
		else:
			where = ""
		query = "SELECT * FROM `{table}` {where} ORDER BY `{order}` ASC;".format(
			table=self.Table,
			where=where,
			order=self.IdField
		)
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor() as cursor:
				return await cursor.execute(query)


	async def search(self, filter: dict = None, sort: dict = None, page: int = 0, limit: int = -1) -> list:
		results = []
		if filter is not None:
			assert len(filter) == 1
			k, v = filter.popitem()
			where = "WHERE `{}` = {}".format(k, v)
		else:
			where = ""
		query = "SELECT * FROM `{table}` {where} ORDER BY `{order}` ASC;".format(
			table=self.Table,
			where=where,
			order=self.IdField
		)

		if limit > 0:
			offset = page * limit
		else:
			offset = 0

		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				nrows = await cursor.execute(query)
				if nrows == 0:
					return []
				try:
					await cursor.scroll(offset)
				except IndexError:
					L.error("MySQL: Out of range", struct_data={"query": query, "scroll": offset})
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
		if filtr is not None:
			where = "WHERE {} = {}".format(self.Fields["username"], filtr)
		else:
			where = ""
		query = "SELECT * FROM `{table}` {where} ORDER BY `{order}` ASC;".format(
			table=self.Table,
			where=where,
			order=self.IdField
		)
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor(aiomysql.DictCursor) as cursor:
				nrows = await cursor.execute(query)
				if nrows == 0:
					return
				try:
					await cursor.scroll(offset)
				except IndexError:
					L.error("MySQL: Out of range", struct_data={"query": query, "scroll": offset})
					return
				result = await cursor.fetchone()
				while result is not None:
					yield self._nomalize_credentials(result)
					if limit > 0:
						limit -= 1
					if limit == 0:
						return
					result = await cursor.fetchone()


	async def get_login_descriptors(self, credentials_id):
		raise NotImplementedError()


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
			L.error("Authentication failed: Credentials contain no password", struct_data={"cid": credentials_id})
		return False


	def _nomalize_credentials(self, db_obj, include=None):
		normalized = {
			'_id': "{}:{}:{}".format(self.Type, self.ProviderID, db_obj[self.IdField]),
			'_type': self.Type,
			'_provider_id': self.ProviderID,
		}
		for field, db_field in self.Fields.items():
			if db_field in db_obj:
				normalized[field] = db_obj[db_field]

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
