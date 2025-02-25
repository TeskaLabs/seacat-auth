import abc
import typing

import asab


class TenantsProviderABC(asab.Configurable, abc.ABC):


	def __init__(self, provider_id, config_section_name, config=None):
		super().__init__(config_section_name=config_section_name, config=config)
		self.ProviderID = provider_id


	@abc.abstractmethod
	async def iterate(self, page: int = 10, limit: int = None, filter: str = None):
		pass


	@abc.abstractmethod
	async def count(self, filter: str = None) -> int:
		pass


	@abc.abstractmethod
	async def iterate_assigned(self, credatials_id: str, page: int = 10, limit: int = None):
		pass


	@abc.abstractmethod
	async def get_assignment(self, credatials_id: str, tenant: str):
		pass


class EditableTenantsProviderABC(TenantsProviderABC):

	@abc.abstractmethod
	async def create(self, tenant: dict) -> typing.Optional[str]:
		pass

	@abc.abstractmethod
	async def delete(self, tenant_id: str) -> typing.Optional[str]:
		pass

	@abc.abstractmethod
	async def update(self, tenant_id: str, **kwargs) -> typing.Optional[str]:
		pass
