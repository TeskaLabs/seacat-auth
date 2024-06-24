import datetime
import logging
import typing

import asab
import asab.web.rest

from ..utils import AuthOperation
from ...events import EventTypes


#

L = logging.getLogger(__name__)

#


class ExternalLoginStateStorage:

	ExternalLoginStateCollection = "els"

	def __init__(self, app):
		self.StorageService = app.get_service("asab.StorageService")
		self.StateExpiration = datetime.timedelta(seconds=asab.Config.getseconds(
			"seacatauth:external_login", "state_expiration"))
		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


	async def _on_housekeeping(self, event_name):
		await self._delete_expired()


	async def create(
		self,
		state_id: str,
		provider_type: str,
		operation: AuthOperation,
		redirect_uri: typing.Optional[str],
		nonce: typing.Optional[str]
	):
		upsertor = self.StorageService.upsertor(self.ExternalLoginStateCollection, obj_id=state_id)
		upsertor.set("provider", provider_type)
		upsertor.set("operation", operation.value)
		if redirect_uri:
			upsertor.set("redirect_uri", redirect_uri)
		if nonce:
			upsertor.set("nonce", nonce)
		state_id = await upsertor.execute(event_type=EventTypes.EXTERNAL_LOGIN_STATE_CREATED)
		return state_id


	async def get(self, state_id):
		state = await self.StorageService.get(self.ExternalLoginStateCollection, state_id)
		if state["_c"] < datetime.datetime.now(datetime.timezone.utc) - self.StateExpiration:
			raise KeyError(state_id)
		state["operation"] = AuthOperation.deserialize(state["operation"])
		return state


	async def update(self, state_id):
		raise NotImplementedError()


	async def delete(self, state_id):
		return await self.StorageService.delete(self.ExternalLoginStateCollection, state_id)


	async def _delete_expired(self):
		collection = self.StorageService.Database[self.ExternalLoginStateCollection]
		query = {"_c": {"$lt": datetime.datetime.now(datetime.timezone.utc) - self.StateExpiration}}
		result = await collection.delete_many(query)
		if result.deleted_count > 0:
			L.info("Expired external login states deleted.", struct_data={
				"count": result.deleted_count
			})
