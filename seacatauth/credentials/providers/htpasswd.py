import logging
import functools
from typing import Optional

from passlib.apache import HtpasswdFile

import asab
from .abc import CredentialsProviderABC

#

L = logging.getLogger(__name__)

#


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
		self.HT = HtpasswdFile(self.Config['path'])


	async def locate(self, ident: str, ident_fields: dict = None, login_dict: dict = None) -> str:
		# TODO: Implement ident_fields support
		'''
		Locate search for the exact match of provided ident and the username in the htpasswd file
		'''
		self.HT.load_if_changed()
		if ident not in frozenset(self.HT.users()):
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


	async def get(self, credentials_id, include=None) -> Optional[dict]:
		prefix = "{}:{}:".format(self.Type, self.ProviderID)
		if not credentials_id.startswith(prefix):
			raise KeyError("Credentials '{}' not found".format(credentials_id))

		self.HT.load_if_changed()

		username = credentials_id[len(prefix):]
		if username not in frozenset(self.HT.users()):
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

		self.HT.load_if_changed()
		if self.HT.check_password(username, password):
			return True

		return False


	async def count(self, filtr=None) -> int:
		if filtr is None:
			return len(self.HT.users())

		def filter_fnct(x, y):
			if filtr in y:
				return x + 1
			else:
				return x

		return functools.reduce(filter_fnct, self.HT.users(), 0)


	async def search(self, filter: dict = None, **kwargs) -> list:
		# TODO: Implement filtering and pagination
		if filter is not None:
			return []
		prefix = "{}:{}:".format(self.Type, self.ProviderID)
		return [
			{
				'_id': prefix + username,
				'_type': self.Type,
				'_provider_id': self.ProviderID,
				'username': username,
			} for username in self.HT.users()
		]


	async def iterate(self, offset: int = 0, limit: int = -1, filtr: str = None):
		prefix = "{}:{}:".format(self.Type, self.ProviderID)

		if filtr is None:
			arr = self.HT.users()
		else:
			arr = [u for u in self.HT.users() if filtr in u]

		for username in arr[offset:None if limit == -1 else limit + offset]:
			yield {
				'_id': prefix + username,
				'_type': self.Type,
				'_provider_id': self.ProviderID,
				'username': username,
			}
