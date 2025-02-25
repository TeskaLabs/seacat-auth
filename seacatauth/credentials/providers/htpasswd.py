import logging
import functools
import os
import typing

import asab
from .abc import CredentialsProviderABC


L = logging.getLogger(__name__)


class HTPasswdCredentialsService(asab.Service):

	def __init__(self, app, service_name='seacatauth.credentials.htpasswd'):
		super().__init__(app, service_name)

	def create_provider(self, provider_id, config_section_name):
		return HTPasswdCredentialsProvider(provider_id, config_section_name)


class HTPasswdCredentialsProvider(CredentialsProviderABC):

	Type = "htpasswd"

	ConfigDefaults = {
		'path': 'htpasswd',
	}

	def __init__(self, provider_id, config_section_name):
		super().__init__(provider_id, config_section_name)
		self._Path = self.Config["path"]
		self._Dict = {}
		self._MTime = 0
		self._refresh()

	def _refresh(self):
		if self._Dict and self._MTime == os.path.getmtime(self._Path):
			# Reload not needed
			return

		with open(self._Path, "r") as f:
			for line in f:
				username, password = line.strip().split(":", 1)
				self._Dict[username] = password


	async def locate(self, ident: str, ident_fields: dict = None, login_dict: dict = None) -> str:
		# TODO: Implement ident_fields support
		"""
		Locate search for the exact match of provided ident and the username in the htpasswd file
		"""
		self._refresh()
		if ident not in self._Dict:
			return None
		return "{}:{}:{}".format(self.Type, self.ProviderID, ident)


	async def get_login_descriptors(self, credentials_id):
		'''
		htpasswd support only password-based logins
		'''
		return [{
			'id': 'default',
			'label': 'Use recommended login.',
			'factors': [{
				'id': 'password',
				'type': 'password'
			}],
		}]


	async def get(self, credentials_id, include=None) -> typing.Optional[dict]:
		prefix = "{}:{}:".format(self.Type, self.ProviderID)
		if not credentials_id.startswith(prefix):
			raise KeyError("Credentials '{}' not found".format(credentials_id))

		self._refresh()

		username = credentials_id[len(prefix):]
		if username not in self._Dict:
			raise KeyError("Credentials '{}' not found".format(credentials_id))

		return {
			'_id': prefix + username,
			'_type': self.Type,
			'_provider_id': self.ProviderID,
			"username": username,
		}


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		provider_type, provider_id, username = credentials_id.split(':', 3)

		if provider_type != self.Type:
			return False

		if provider_id != self.ProviderID:
			return False

		password = credentials.get('password', '')

		self._refresh()
		password_hash = self._Dict.get(username)
		if not password_hash:
			return False

		if self._verify_password(password_hash, password):
			return True

		return False


	async def count(self, filtr=None) -> int:
		self._refresh()
		if filtr is None:
			return len(self._Dict)

		def filter_fnct(x, y):
			if filtr in y:
				return x + 1
			else:
				return x

		return functools.reduce(filter_fnct, self._Dict.keys(), 0)


	async def search(self, filter: dict = None, **kwargs) -> list:
		self._refresh()
		if filter is not None:
			return []
		prefix = "{}:{}:".format(self.Type, self.ProviderID)
		return [
			{
				'_id': prefix + username,
				'_type': self.Type,
				'_provider_id': self.ProviderID,
				'username': username,
			} for username in self._Dict
		]


	async def iterate(self, offset: int = 0, limit: int = -1, filtr: str = None):
		self._refresh()
		prefix = "{}:{}:".format(self.Type, self.ProviderID)

		if filtr is None:
			arr = list(self._Dict.keys())
		else:
			arr = [u for u in self._Dict if filtr in u]

		for username in arr[offset: None if limit == -1 else limit + offset]:
			yield {
				'_id': prefix + username,
				'_type': self.Type,
				'_provider_id': self.ProviderID,
				'username': username,
			}
