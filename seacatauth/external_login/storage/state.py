import datetime
import logging

import asab
import asab.web.rest

from ..utils import AuthOperation
from ...events import EventTypes


#

L = logging.getLogger(__name__)

#


class StateStorage:
	def __init__(self, storage_service, collection_name: str):
		self.StorageService = storage_service
		self.CollectionName = collection_name
		self.StateExpiration = datetime.timedelta(seconds=asab.Config.getseconds(
			"seacatauth:external_login", "state_expiration"))

	async def create(
		self,
		state_id: str,
		provider_type: str,
		action: AuthOperation,
		redirect_uri: str,
		nonce: str
	):
		upsertor = self.StorageService.upsertor(self.CollectionName, obj_id=state_id)
		upsertor.set("type", provider_type)
		upsertor.set("action", action.value)
		upsertor.set("redirect_uri", redirect_uri)
		upsertor.set("nonce", nonce)
		state_id = await upsertor.execute(event_type=EventTypes.EXTERNAL_LOGIN_STATE_CREATED)
		return state_id


	async def get(self, state_id):
		return await self.StorageService.get(self.CollectionName, state_id)


	async def update(self, state_id):
		raise NotImplementedError("Updating external login state is not implemented.")


	async def delete(self, state_id):
		return await self.StorageService.delete(self.CollectionName, state_id)
