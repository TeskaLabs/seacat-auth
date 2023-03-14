import logging

import aiohttp

import asab
from .abc import CredentialsProviderABC

#

L = logging.getLogger(__name__)

#


class ElasticSearchCredentialsService(asab.Service):

	def __init__(self, app, service_name='seacatauth.credentials.elasticsearch'):
		super().__init__(app, service_name)

	def create_provider(self, provider_id, config_section_name):
		return ElasticSearchCredentialsProvider(provider_id, config_section_name)


class ElasticSearchCredentialsProvider(CredentialsProviderABC):

	Type = "elasticsearch"

	ConfigDefaults = {
		'url': 'http://localhost:9200/',
		'username': 'elastic',
		'password': 'elastic',
	}


	def __init__(self, provider_id, config_section_name):
		super().__init__(provider_id, config_section_name)
		self.BaseUrl = self.Config['url']
		self.BasicAuth = aiohttp.BasicAuth(self.Config['username'], self.Config['password'])


	async def _load_users(self):
		async with aiohttp.ClientSession(auth=self.BasicAuth) as session:
			async with session.get(self.BaseUrl + '_security/user') as resp:
				if resp.status != 200:
					return None
				return await resp.json()


	async def count(self) -> int:
		'''
		Non-authoritative count of the credentials managed by the provider.
		It is used for indicative information on the UI.

		Should return -1 if unable to count credentials managed.
		'''

		users = await self._load_users()
		if users is None:
			return None

		return len(users)


	async def search(self) -> list:
		users = await self._load_users()
		return [self._nomalize_credentials(username, user) for username, user in users.items()]


	async def get(self, credentials_id, include=None) -> dict:
		prefix = "{}:{}:".format(self.Type, self.ProviderID)
		if not credentials_id.startswith(prefix):
			raise KeyError("Credentials '{}' not found".format(credentials_id))

		username = credentials_id[len(prefix):]

		async with aiohttp.ClientSession(auth=self.BasicAuth) as session:
			async with session.get(self.BaseUrl + '_security/user/' + username) as resp:
				if resp.status != 200:
					L.warning("Elastic responsed with {}\n{}".format(resp, await resp.text()))
					return None
				f = await resp.json()

		return self._nomalize_credentials(username, f[username])


	def _nomalize_credentials(self, username, user):
		obj = {
			'_id': "{}:{}:{}".format(self.Type, self.ProviderID, username),
			'_type': self.Type,
			'_provider_id': self.ProviderID,
			'username': username,
		}

		v = user.get('full_name')
		if v is not None:
			obj['full_name'] = v

		v = user.get('email')
		if v is not None:
			obj['email'] = v

		v = user.get('enabled')
		if v is False:
			obj['suspended'] = not v

		obj['_es'] = user

		return obj


	async def locate(self, ident: str, ident_fields: dict = None, login_dict: dict = None) -> str:
		query = {"query": {"bool": {
			"filter": [
				{"match_phrase": {"type": "user"}},
				{"match_phrase": {"enabled": True}}
			],
			"should": [
				{"term": {"username": ident}},
				{"term": {"email": ident}}
			],
			"minimum_should_match": 1
		}}}

		async with aiohttp.ClientSession(auth=self.BasicAuth) as session:
			async with session.post(self.BaseUrl + '.security-*/_search', json=query) as resp:
				if resp.status != 200:
					L.warning("Elastic responsed with {}\n{}".format(resp, await resp.text()))
					return None
				r = await resp.json()

		r = r.get('hits', []).get('hits', [])
		if len(r) == 0:
			return None
		r = r[0]

		return "{}:{}:{}".format(self.Type, self.ProviderID, r['_source']['username'])


	async def get_login_descriptors(self, credentials_id):
		'''
		ElasticSearch support only password-based logins
		'''
		return [{
			'id': 'default',
			'label': 'Use recommended login.',
			'factors': [{
				'id': 'password',
				'type': 'password'
			}],
		}]


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		provider_type, provider_id, username = credentials_id.split(':', 3)

		if provider_type != self.Type:
			return False

		if provider_id != self.ProviderID:
			return False

		basic_auth = aiohttp.BasicAuth(username, credentials.get('password', ''))

		async with aiohttp.ClientSession(auth=basic_auth) as session:
			async with session.get(self.BaseUrl + '_security/_authenticate') as resp:
				if resp.status == 401:
					return False

				if resp.status != 200:
					L.warning("Elastic responsed with {}\n{}".format(resp, await resp.text()))
					return False

				await resp.json()

		return True
