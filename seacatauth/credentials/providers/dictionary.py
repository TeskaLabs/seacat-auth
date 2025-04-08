import datetime
import functools
import hashlib
import logging
import typing
import asab

from .abc import EditableCredentialsProviderABC
from ... import generic, exceptions


L = logging.getLogger(__name__)


class DictCredentialsService(asab.Service):

	def __init__(self, app, service_name="seacatauth.credentials.dict"):
		super().__init__(app, service_name)

	def create_provider(self, provider_id, config_section_name):
		return DictCredentialsProvider(self.App, provider_id, config_section_name)


class DictCredentialsProvider(EditableCredentialsProviderABC):
	Type = "dict"
	EditableFields = [
		"email",
		"phone"
	]

	def __init__(self, app, provider_id, config_section_name):
		super().__init__(app, provider_id, config_section_name)
		# TODO: Load creation features from config

		self.Dictionary = {}


	async def create(self, credentials: dict) -> typing.Optional[str]:
		username = credentials.get("username") or credentials.get("email") or credentials.get("phone")
		if username is None:
			raise ValueError("Cannot determine user name")

		obj_id = hashlib.sha224(username.encode("utf-8")).hexdigest()
		if obj_id in self.Dictionary:
			raise ValueError("Already exists.")

		credentials_object = {
			"_id": obj_id,
			"_v": 1,
			"_c": datetime.datetime.now(datetime.timezone.utc),
			"_m": datetime.datetime.now(datetime.timezone.utc),
		}
		if "username" in credentials:
			credentials_object["username"] = credentials["username"]
		if "email" in credentials:
			credentials_object["email"] = credentials["email"]
		if "phone" in credentials:
			credentials_object["phone"] = credentials["phone"]
		if "password" in credentials:
			credentials_object["__password"] = generic.bcrypt_hash(credentials["password"])

		self.Dictionary[obj_id] = credentials_object
		return self._format_credentials_id(obj_id)


	async def update(self, credentials_id, update: dict) -> typing.Optional[str]:
		try:
			obj_id = self._format_object_id(credentials_id)
		except ValueError:
			raise exceptions.CredentialsNotFoundError(credentials_id)

		credentials = self.Dictionary.get(obj_id)
		if credentials is None:
			raise exceptions.CredentialsNotFoundError(credentials_id)

		# Update the password
		if "password" in update:
			new_pwd = update.pop("password")
			credentials["__password"] = generic.bcrypt_hash(new_pwd)

		for k, v in update.items():
			credentials[k] = v

		credentials["_v"] += 1
		credentials["_m"] = datetime.datetime.now(datetime.timezone.utc)

		return credentials_id


	async def delete(self, credentials_id) -> typing.Optional[str]:
		try:
			obj_id = self._format_object_id(credentials_id)
		except ValueError:
			raise exceptions.CredentialsNotFoundError(credentials_id)

		self.Dictionary.pop(obj_id)
		return credentials_id


	async def locate(self, ident: str, ident_fields: dict = None, login_dict: dict = None) -> str:
		# TODO: Implement ident_fields support
		# Fast match based on the username
		obj_id = hashlib.sha224(ident.encode("utf-8")).hexdigest()
		if obj_id in self.Dictionary:
			return self._format_credentials_id(obj_id)

		# Full scan to find matches based on email or phone
		for credentials in self.Dictionary.values():
			username = credentials["username"]
			if ident == credentials.get("email", 0):
				pass
			elif ident == credentials.get("phone", 0):
				pass
			else:
				continue

			obj_id = hashlib.sha224(username.encode("utf-8")).hexdigest()
			return self._format_credentials_id(obj_id)

		return None


	async def get(self, credentials_id, include=None) -> dict:
		try:
			obj_id = self._format_object_id(credentials_id)
		except ValueError:
			raise exceptions.CredentialsNotFoundError(credentials_id)

		credentials = self.Dictionary.get(obj_id)
		if credentials is None:
			raise exceptions.CredentialsNotFoundError(credentials_id)

		# TODO: Allow to include __totp and other fields from `include`
		result = self._normalize_credentials(credentials)

		return result


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		try:
			obj_id = self._format_object_id(credentials_id)
		except ValueError:
			return False

		password = credentials["password"]

		credentials_db = self.Dictionary.get(obj_id)
		if credentials_db is None:
			return False

		if generic.bcrypt_verify(credentials_db["__password"], password):
			return True

		return False


	async def count(self, filtr=None) -> int:
		if filtr is None:
			return len(self.Dictionary)

		def counter(count, cred):
			if filtr in cred["username"]:
				return count + 1
			return count

		return functools.reduce(counter, self.Dictionary.values(), 0)


	async def search(self, filter: dict = None, **kwargs) -> list:
		# TODO: Implement filtering and pagination
		return []


	async def iterate(self, offset: int = 0, limit: int = -1, filtr: str = None):
		for i, credentials in enumerate(self.Dictionary.values()):
			if i < offset:
				continue
			if i > offset + limit:
				break
			if filtr is not None and filtr not in credentials["username"]:
				continue
			yield self._normalize_credentials(credentials)


	def _normalize_credentials(self, db_obj):
		obj = {
			"_id": self._format_credentials_id(db_obj["_id"]),
			"_type": self.Type,
			"_provider_id": self.ProviderID,
		}
		for k, v in db_obj.items():
			if k in frozenset(("_id", "_type", "_provider_id")):
				continue
			if k.startswith("__"):
				continue
			obj[k] = v
		return obj


	async def get_login_descriptors(self, credentials_id):
		return [{
			"id": "default",
			"label": "Use recommended login.",
			"factors": [{
				"id": "password",
				"type": "password"
			}],
		}]
