import datetime
import logging

import asab.storage.exceptions

from .codes import EventCode

#

L = logging.getLogger(__name__)

#

asab.Config.add_defaults({
	"seacatauth:audit": {
		# Enable or disable the auditing of anonymous sessions.
		# Disabling may be desirable for database performance reasons.
		"log_anonymous_sessions": True,
	},
})


class LastActivityService(asab.Service):

	LastActivityCollection = "lce"

	def __init__(self, app, service_name="seacatauth.LastActivityService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")


	async def upsert_last_credentials_event(self, event_code: EventCode, credentials_id: str, **kwargs):
		kwargs["_c"] = datetime.datetime.now(datetime.timezone.utc)

		# Do not use upsertor because it can trigger webhook
		coll = await self.StorageService.collection(self.LastActivityCollection)
		await coll.update_one({"_id": credentials_id}, {"$set": {event_code.name: kwargs}}, upsert=True)


	async def get_last_logins(self, credentials_id: str) -> dict:
		try:
			last_events = await self.StorageService.get(self.LastActivityCollection, credentials_id)
		except KeyError:
			return {}

		result = {}
		successful_login = last_events.get(EventCode.LOGIN_SUCCESS.name)
		if successful_login:
			result["sat"] = successful_login["_c"]
			v = successful_login.get("fi")
			if v is not None:
				result["sfi"] = v

		failed_login = last_events.get(EventCode.LOGIN_FAILED.name)
		if failed_login:
			result["fat"] = failed_login["_c"]
			v = failed_login.get("fi")
			if v is not None:
				result["ffi"] = v

		return result


	async def get_last_password_change(self, credentials_id: str) -> dict:
		try:
			last_events = await self.StorageService.get(self.LastActivityCollection, credentials_id)
		except KeyError:
			return {}

		result = {}
		successful_change = last_events.get(EventCode.PASSWORD_CHANGE_SUCCESS.name)
		if successful_change:
			result["spct"] = successful_change["_c"]
			v = successful_change.get("fi")
			if v is not None:
				result["spcfi"] = v

		failed_change = last_events.get(EventCode.PASSWORD_CHANGE_FAILED.name)
		if failed_change:
			result["fpct"] = failed_change["_c"]
			v = failed_change.get("fi")
			if v is not None:
				result["fpcfi"] = v

		return result


	async def get_last_authorized_tenants(self, credentials_id: str):
		try:
			last_events = await self.StorageService.get(self.LastActivityCollection, credentials_id)
		except KeyError:
			return None

		last_authorization = last_events.get(EventCode.AUTHORIZE_SUCCESS.name)
		if last_authorization:
			return last_authorization.get("tenants")
		else:
			return None
