import pymongo
import logging
import asab
import asab.web.rest
import asab.exceptions
import asab.storage.exceptions

from ...events import EventTypes


L = logging.getLogger(__name__)


class ExternalLoginAccountStorage:

	ExternalLoginAccountCollection = "el"

	def __init__(self, app):
		self.StorageService = app.get_service("asab.StorageService")


	async def initialize(self):
		coll = await self.StorageService.collection(self.ExternalLoginAccountCollection)
		await coll.create_index([("cid", pymongo.ASCENDING)])


	async def create(self, credentials_id: str, provider_type: str, user_info: dict | None = None):
		sub = str(user_info["sub"])
		upsertor = self.StorageService.upsertor(
			self.ExternalLoginAccountCollection,
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

		try:
			external_account_id = await upsertor.execute(event_type=EventTypes.EXTERNAL_LOGIN_CREATED)
		except asab.storage.exceptions.DuplicateError as e:
			raise asab.exceptions.Conflict("External account already registered") from e
		L.log(asab.LOG_NOTICE, "External login account added", struct_data={
			"id": external_account_id,
			"cid": credentials_id,
		})
		return external_account_id


	async def get(self, provider_type: str, sub: str):
		account = await self.StorageService.get(self.ExternalLoginAccountCollection, _make_id(provider_type, sub))
		account = _add_back_compat_fields(account)
		return account


	async def list(self, credentials_id: str):
		collection = self.StorageService.Database[self.ExternalLoginAccountCollection]
		query = {"cid": credentials_id}
		cursor = collection.find(query)
		cursor.sort("_c", -1)

		accounts = []
		async for account in cursor:
			accounts.append(_add_back_compat_fields(account))

		return accounts


	async def update(self, provider_type: str, sub: str, **kwargs):
		raise NotImplementedError()


	async def delete(self, provider_type: str, sub: str):
		return await self.StorageService.delete(self.ExternalLoginAccountCollection, _make_id(provider_type, sub))


def _make_id(provider_type: str, sub: str):
	return "{} {}".format(provider_type, sub)


def _add_back_compat_fields(account: dict):
	if "e" in account and "email" not in account:
		account["email"] = account["e"]
	if "s" in account and "sub" not in account:
		account["sub"] = account["s"]
	if "t" in account and "type" not in account:
		account["type"] = account["t"]
	return account
