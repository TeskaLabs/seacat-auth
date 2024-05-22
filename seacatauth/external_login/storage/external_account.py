import datetime
import pymongo
import logging

import asab
import asab.web.rest

from ..utils import AuthOperation
from ...events import EventTypes


#

L = logging.getLogger(__name__)

#


class ExternalAccountStorage:
	def __init__(self, storage_service, collection_name: str):
		self.StorageService = storage_service
		self.CollectionName = collection_name


	async def initialize(self):
		coll = await self.StorageService.collection(self.CollectionName)
		await coll.create_index([("cid", pymongo.ASCENDING)])


	async def create(self, credentials_id: str, provider_type: str, user_info: dict | None = None):
		sub = str(user_info["sub"])
		upsertor = self.StorageService.upsertor(
			self.CollectionName,
			obj_id=_make_id(provider_type, sub)
		)
		upsertor.set("type", provider_type)
		upsertor.set("sub", sub)
		upsertor.set("cid", credentials_id)

		email = user_info.get("email")
		if email is not None:
			upsertor.set("email", email)

		phone = user_info.get("phone_number")
		if phone is not None:
			upsertor.set("phone", phone)

		username = user_info.get("preferred_username")
		if username is not None:
			upsertor.set("username", username)

		external_account_id = await upsertor.execute(event_type=EventTypes.EXTERNAL_LOGIN_CREATED)
		L.log(asab.LOG_NOTICE, "External login credential created", struct_data={
			"id": external_account_id,
			"cid": credentials_id,
		})
		return external_account_id


	async def get(self, provider_type: str, sub: str):
		return await self.StorageService.get(self.CollectionName, _make_id(provider_type, sub))


	async def list(self, credentials_id: str):
		raise NotImplementedError()


	async def update(self, state_id):
		raise NotImplementedError()


	async def delete(self, provider_type: str, sub: str):
		return await self.StorageService.delete(self.CollectionName, _make_id(provider_type, sub))


def _make_id(provider_type: str, sub: str):
	return "{} {}".format(provider_type, sub)
