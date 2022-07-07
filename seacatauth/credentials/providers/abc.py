import abc
import logging
from typing import Optional

import asab

#

L = logging.getLogger(__name__)

#


class CredentialsProviderABC(asab.ConfigObject, abc.ABC):

	Type = "abc"
	Editable = False

	ConfigDefaults = {
		'tenants': 'no',
		'register': 'no',  # Yes, if this credentials provider handles registration
	}

	def __init__(self, provider_id, config_section_name, config=None):
		super().__init__(config_section_name=config_section_name, config=config)
		self.ProviderID = provider_id
		self.Prefix = "{}:{}:".format(self.Type, self.ProviderID)
		order = self.Config.get("order", 10)
		self.Order = int(order)


	async def locate(self, ident: str, ident_fields: dict = None) -> str:
		'''
		Locate credentials based on the vague 'ident', which could be the username, password, phone number etc.
		Return credentials_id or return None if not found.
		'''
		return None

	async def get_by(self, key: str, value) -> Optional[dict]:
		"""
		Get credentials by an indexed key
		"""
		return None

	async def get_login_descriptors(self, credentials_id) -> list:
		'''
		Create a descriptor for the allowed login configurations
		'''
		return []


	async def detail(self, credentials_id) -> Optional[dict]:
		'''
		Obsolete, use get()
		'''
		L.warning("Obsolete method used -> CredentialsProvider.detail :-(")
		return await self.get(credentials_id)


	@abc.abstractmethod
	async def get(self, credentials_id, include=None) -> Optional[dict]:
		raise NotImplementedError('in {}'.format(self.Type))


	@abc.abstractmethod
	async def count(self, filtr: str = None) -> int:
		'''
		Non-authoritative count of the credentials managed by the provider.
		It is used for indicative information on the UI.

		Should return -1 if unable to count credentials managed.
		'''
		return -1


	@abc.abstractmethod
	async def search(self, filter: dict = None, **kwargs) -> list:
		return []

	async def iterate(self, offset: int = 0, limit: int = -1, filtr: str = None):
		for item in []:
			yield item


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		return False

	async def register(self, register_info: dict) -> Optional[str]:
		pass

	def get_info(self) -> dict:
		'''
		Get info about this provider.
		'''
		return {
			'_type': self.Type,
			'_provider_id': self.ProviderID,
			'_order': self.Order,
		}



class EditableCredentialsProviderABC(CredentialsProviderABC):

	Editable = True

	@abc.abstractmethod
	async def create(self, credentials: dict) -> Optional[str]:
		pass

	@abc.abstractmethod
	async def update(self, credentials_id, credentials: dict) -> Optional[str]:
		pass

	@abc.abstractmethod
	async def delete(self, credentials_id) -> Optional[str]:
		pass
