import datetime
import logging

import asab.storage.exceptions

from .codes import AuditCode

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


class AuditService(asab.Service):

	AuditCollection = "a"
	LastCredentialsEventCollection = "lce"
	LastCredentialsEventCodes = frozenset([
		AuditCode.LOGIN_SUCCESS,
		AuditCode.LOGIN_FAILED,
		AuditCode.PASSWORD_CHANGE_SUCCESS,
		AuditCode.PASSWORD_CHANGE_FAILED,
		AuditCode.AUTHORIZE_SUCCESS])

	def __init__(self, app, service_name="seacatauth.AuditService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.IsAnonymousLoggingEnabled = asab.Config.getboolean("seacatauth:audit", "log_anonymous_sessions")


	async def append(
		self, code: AuditCode, *,
		credentials_id: str = None,
		client_id: str = None,
		session_id: str = None,
		tenant: str = None,
		**kwargs
	):
		"""
		Records a new audit entry.
		"""
		assert (isinstance(code, AuditCode))

		# Do not audit anonymous sessions if desired (performance reasons)
		if code == AuditCode.ANONYMOUS_SESSION_CREATED and not self.IsAnonymousLoggingEnabled:
			return

		# Do not use upsertor because it can trigger webhook
		now = datetime.datetime.now(datetime.timezone.utc)
		entry = {
			"_c": now,
			"c": code.name
		}
		if credentials_id is not None:
			entry["cid"] = credentials_id
		if client_id is not None:
			entry["clid"] = client_id
		if session_id is not None:
			entry["sid"] = session_id
		if tenant is not None:
			entry["t"] = tenant
		entry.update(kwargs)

		coll = await self.StorageService.collection(self.AuditCollection)
		await coll.insert_one(entry)

		if code in self.LastCredentialsEventCodes:
			await self._upsert_last_credentials_event(code, credentials_id, **kwargs)


	async def _upsert_last_credentials_event(self, code: AuditCode, credentials_id: str, **kwargs):
		kwargs["_c"] = datetime.datetime.now(datetime.timezone.utc)

		# Do not use upsertor because it can trigger webhook
		coll = await self.StorageService.collection(self.LastCredentialsEventCollection)
		await coll.update_one({"_id": credentials_id}, {"$set": {code.name: kwargs}}, upsert=True)


	async def delete_old_entries(self, before_datetime: datetime.datetime):
		coll = await self.StorageService.collection(self.AuditCollection)
		result = await coll.delete_many({"_c": {"$lt": before_datetime}})
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Old audit entries deleted.", struct_data={
				"count": result.deleted_count
			})
		return result.deleted_count


	async def get_last_logins(self, credentials_id: str) -> dict:
		try:
			last_events = await self.StorageService.get(self.LastCredentialsEventCollection, credentials_id)
		except KeyError:
			return {}

		result = {}
		successful_login = last_events.get(AuditCode.LOGIN_SUCCESS.name)
		if successful_login:
			result["sat"] = successful_login["_c"]
			v = successful_login.get("fi")
			if v is not None:
				result["sfi"] = v

		failed_login = last_events.get(AuditCode.LOGIN_FAILED.name)
		if failed_login:
			result["fat"] = failed_login["_c"]
			v = failed_login.get("fi")
			if v is not None:
				result["ffi"] = v

		return result


	async def get_last_password_change(self, credentials_id: str) -> dict:
		try:
			last_events = await self.StorageService.get(self.LastCredentialsEventCollection, credentials_id)
		except KeyError:
			return {}

		result = {}
		successful_change = last_events.get(AuditCode.PASSWORD_CHANGE_SUCCESS.name)
		if successful_change:
			result["spct"] = successful_change["_c"]
			v = successful_change.get("fi")
			if v is not None:
				result["spcfi"] = v

		failed_change = last_events.get(AuditCode.PASSWORD_CHANGE_FAILED.name)
		if failed_change:
			result["fpct"] = failed_change["_c"]
			v = failed_change.get("fi")
			if v is not None:
				result["fpcfi"] = v

		return result


	async def get_last_authorized_tenants(self, credentials_id: str):
		try:
			last_events = await self.StorageService.get(self.LastCredentialsEventCollection, credentials_id)
		except KeyError:
			return None

		last_authorization = last_events.get(AuditCode.AUTHORIZE_SUCCESS.name)
		if last_authorization:
			return last_authorization.get("tenants")
		else:
			return None
