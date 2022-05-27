import logging
from typing import Optional

import asab
import aiomysql

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
			self.ConnectionParams["passwd"] = password

		self.Table = self.Config.get("table")

		self.Fields = {
			"username": self.Config.get("field_username"),
			"email": self.Config.get("field_email"),
			"phone": self.Config.get("field_phone"),
			"password": self.Config.get("field_password"),
		}

		data_fields = self.Config.get("data_fields")
		if len(data_fields) > 0:
			self.DataFields = data_fields.split(" ")
		else:
			self.DataFields = None


	async def create(self, credentials: dict) -> Optional[str]:
		raise NotImplementedError()


	async def register(self, register_info: dict) -> Optional[str]:
		raise NotImplementedError()


	async def update(self, credentials_id, update: dict) -> Optional[str]:
		raise NotImplementedError()


	async def delete(self, credentials_id) -> Optional[str]:
		raise NotImplementedError()


	async def locate(self, ident: str, ident_fields: dict = None) -> Optional[str]:
		raise NotImplementedError()


	async def get_by(self, key: str, value) -> Optional[dict]:
		raise NotImplementedError()


	async def get_by_external_login_sub(self, login_provider: str, sub_id: str) -> Optional[dict]:
		raise NotImplementedError()


	async def get(self, credentials_id, include=None) -> Optional[dict]:
		async with aiomysql.connect(**self.ConnectionParams) as connection:
			async with connection.cursor() as cursor:
				await cursor.execute("FROM {table} SELECT * WHERE {field}={value};".format(
					table=self.Table,
					field=self.Fields["id"],
					value=credentials_id,
				))
				result = await cursor.fetchone
		return result


	async def count(self, filtr=None) -> int:
		raise NotImplementedError()


	async def search(self, filter: dict = None, sort: dict = None, page: int = 0, limit: int = 0) -> list:
		raise NotImplementedError()


	async def iterate(self, offset: int = 0, limit: int = -1, filtr: str = None):
		raise NotImplementedError()


	def _nomalize_credentials(self, db_obj, include=None):
		raise NotImplementedError()


	async def get_login_descriptors(self, credentials_id):
		raise NotImplementedError()


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		raise NotImplementedError()


def authn_password(dbcred, credentials):
		raise NotImplementedError()
