import datetime
import functools
import hashlib
import logging
from typing import Optional

from passlib.hash import bcrypt

import asab
from .abc import EditableCredentialsProviderABC

#

L = logging.getLogger(__name__)


#


class DictCredentialsService(asab.Service):

	def __init__(self, app, service_name='seacatauth.credentials.dict'):
		super().__init__(app, service_name)

	def create_provider(self, provider_id, config_section_name):
		# TODO: Check bcrypt.get_backend() - see https://passlib.readthedocs.io/en/stable/lib/passlib.hash.bcrypt.html#index-0
		return DictCredentialsProvider(provider_id, config_section_name)


class DictCredentialsProvider(EditableCredentialsProviderABC):
	Type = "dict"
	EditableFields = [
		"email",
		"phone"
	]

	def __init__(self, provider_id, config_section_name):
		super().__init__(provider_id, config_section_name)
		# TODO: Load creation features from config

		self.Dictionary = {}

	def get_info(self) -> dict:
		info = super().get_info()
		info["registration"] = [
			{'type': 'email'},
			{'type': 'password'}
		]
		info["creation"] = [
			{'type': 'email'},
			{'type': 'password'}
		]
		info["update"] = [
			{"type": field} for field in self.EditableFields
		]
		return info

	async def create(self, credentials: dict) -> Optional[str]:
		username = credentials.get("username")
		if username is None:
			username = credentials.get("email")
		if username is None:
			raise ValueError("Cannot determine user name")

		hashedpwd = bcrypt.hash(credentials["password"].encode('utf-8'))

		credentials_id = hashlib.sha224(username.encode('utf-8')).hexdigest()
		if credentials_id in self.Dictionary:
			raise ValueError("Already exists.")

		credentials_object = {
			"_id": credentials_id,
			"_v": 1,
			"_c": datetime.datetime.utcnow(),
			"_m": datetime.datetime.utcnow(),
			"username": username,
			"__password": hashedpwd,
		}
		if "email" in credentials:
			credentials_object["email"] = credentials.get("email")
		if "phone" in credentials:
			credentials_object["phone"] = credentials.get("phone")

		self.Dictionary[credentials_id] = credentials_object
		return "{}:{}:{}".format(self.Type, self.ProviderID, credentials_id)

	async def update(self, credentials_id, update: dict) -> Optional[str]:
		prefix = "{}:{}:".format(self.Type, self.ProviderID)
		if not credentials_id.startswith(prefix):
			raise KeyError("Credentials '{}' not found".format(credentials_id))

		credentials = self.Dictionary.get(credentials_id[len(prefix):])
		if credentials is None:
			raise KeyError("Credentials '{}' not found".format(credentials_id))

		# Update the password
		if "password" in update:
			new_pwd = update.pop("password")
			credentials["__password"] = bcrypt.hash(new_pwd.encode('utf-8'))

		for k, v in update.items():
			credentials[k] = v

		credentials["_v"] += 1
		credentials["_m"] = datetime.datetime.utcnow()

		return "OK"

	async def delete(self, credentials_id) -> Optional[str]:
		prefix = "{}:{}:".format(self.Type, self.ProviderID)
		self.Dictionary.pop(credentials_id[len(prefix):])
		return "OK"

	async def locate(self, ident: str, ident_fields: dict = None) -> str:
		# TODO: Implement ident_fields support
		# Fast match based on the username
		credentials_id = hashlib.sha224(ident.encode('utf-8')).hexdigest()
		if credentials_id in self.Dictionary:
			return "{}:{}:{}".format(self.Type, self.ProviderID, credentials_id)

		# Full scan to find matches based on email or phone
		for credentials in self.Dictionary.values():
			username = credentials['username']
			if ident == credentials.get('email', 0):
				pass
			elif ident == credentials.get('phone', 0):
				pass
			else:
				continue

			credentials_id = hashlib.sha224(username.encode('utf-8')).hexdigest()
			return "{}:{}:{}".format(self.Type, self.ProviderID, credentials_id)

		return None

	async def get(self, credentials_id, include=None) -> dict:
		prefix = "{}:{}:".format(self.Type, self.ProviderID)
		if not credentials_id.startswith(prefix):
			raise KeyError("Credentials '{}' not found".format(credentials_id))
		credentials = self.Dictionary.get(credentials_id[len(prefix):])
		if credentials is None:
			raise KeyError("Credentials '{}' not found".format(credentials_id))

		# TODO: Allow to include __totp and other fields from `include`
		result = self._normalize_credentials(credentials)

		return result

	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		prefix = "{}:{}:".format(self.Type, self.ProviderID)
		if not credentials_id.startswith(prefix):
			return False

		password = credentials["password"]

		credentials_db = self.Dictionary.get(credentials_id[len(prefix):])
		if credentials_db is None:
			return False

		if bcrypt.verify(password, credentials_db["__password"]):
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
			"_id": "{}:{}:{}".format(self.Type, self.ProviderID, db_obj["_id"]),
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
			'id': 'default',
			'label': 'Use recommended login.',
			'factors': [{
				'id': 'password',
				'type': 'password'
			}],
		}]
