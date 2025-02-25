import abc
import logging
import typing

import asab

from ... import generic

#

L = logging.getLogger(__name__)

#


class CredentialsProviderABC(asab.Configurable, abc.ABC):

	Type = "abc"
	Editable = False
	RegistrationEnabled = False

	ConfigDefaults = {
		"tenants": "no",
		"registration": "no",  # Yes, if this provider allows inviting and registering new users
	}

	def __init__(self, provider_id, config_section_name, config=None):
		super().__init__(config_section_name=config_section_name, config=config)
		self.ProviderID = provider_id
		self.Prefix = "{}:{}:".format(self.Type, self.ProviderID)
		order = self.Config.get("order", 10)
		self.Order = int(order)


	def get_info(self) -> dict:
		"""
		Get info about this provider.
		"""
		return {
			"_type": self.Type,
			"_provider_id": self.ProviderID,
			"_order": self.Order,
			"editable": self.Editable,
		}


	async def locate(self, ident: str, ident_fields: dict = None, login_dict: dict = None) -> str:
		"""
		Locate credentials based on the vague 'ident', which could be the username, password, phone number etc.
		Return credentials_id or return None if not found.
		"""
		return None

	async def get_by(self, key: str, value) -> typing.Optional[dict]:
		"""
		Get credentials by an indexed key
		"""
		return None

	async def get_login_descriptors(self, credentials_id) -> list:
		"""
		Create a descriptor for the allowed login configurations
		"""
		return []


	@abc.abstractmethod
	async def get(self, credentials_id, include=None) -> typing.Optional[dict]:
		raise NotImplementedError('in {}'.format(self.Type))


	@abc.abstractmethod
	async def count(self, filtr: str = None) -> int:
		"""
		Non-authoritative count of the credentials managed by the provider.
		It is used for indicative information on the UI.

		Should return None if unable to count credentials managed.
		"""
		return None


	@abc.abstractmethod
	async def search(self, filter: dict = None, **kwargs) -> list:
		return []

	async def iterate(self, offset: int = 0, limit: int = -1, filtr: str = None):
		for item in []:
			yield item


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		return False


	def _verify_password(self, hash: str, password: str) -> bool:
		"""
		Check if the password matches the hash.
		"""
		if hash.startswith("$2b$") or hash.startswith("$2a$") or hash.startswith("$2y$"):
			return generic.bcrypt_verify(hash, password)
		elif hash.startswith("$argon2id$"):
			return generic.argon2_verify(hash, password)
		else:
			L.warning("Unknown password hash function: {}".format(hash[:4]))
			return False



class EditableCredentialsProviderABC(CredentialsProviderABC):

	Editable = True
	RegistrationEnabled = False

	@abc.abstractmethod
	async def create(self, credentials: dict) -> typing.Optional[str]:
		pass

	@abc.abstractmethod
	async def update(self, credentials_id, credentials: dict) -> typing.Optional[str]:
		pass

	@abc.abstractmethod
	async def delete(self, credentials_id) -> typing.Optional[str]:
		pass
