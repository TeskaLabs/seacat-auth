import datetime
import logging

import asab.storage.exceptions

from .codes import AuditCode

#

L = logging.getLogger(__name__)

#


class AuditService(asab.Service):


	AuditCollection = 'a'


	def __init__(self, app, service_name="seacatauth.AuditService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")


	async def append(self, code: AuditCode, attributes: dict = None):
		assert (isinstance(code, AuditCode))


		if attributes is None:
			attributes = {}
		else:
			attributes = attributes.copy()

		now = datetime.datetime.now(datetime.timezone.utc)
		attributes['_c'] = now
		attributes['_m'] = now
		attributes['c'] = code.name

		coll = await self.StorageService.collection(self.AuditCollection)
		await coll.insert_one(attributes)


	async def _get_latest_entry(self, field_name, **kwargs) -> dict:
		coll = await self.StorageService.collection(self.AuditCollection)
		entry = await coll.find_one(
			filter={
				'c': field_name,
				**kwargs
			},
			sort=[
				('_c', -1)
			]
		)
		return entry


	async def get_last_logins(self, credentials_id: str) -> dict:
		result = {}

		ls = await self._get_latest_entry(AuditCode.LOGIN_SUCCESS.name, cid=credentials_id)
		if ls is not None:
			result['sat'] = ls['_c']
			v = ls.get('fi')
			if v is not None:
				result['sfi'] = v

		lf = await self._get_latest_entry(AuditCode.LOGIN_FAILED.name, cid=credentials_id)
		if lf is not None:
			result['fat'] = lf['_c']
			v = lf.get('fi')
			if v is not None:
				result['ffi'] = v

		return result


	async def get_last_password_change(self, credentials_id: str) -> dict:
		result = {}

		entry = await self._get_latest_entry(AuditCode.PASSWORD_CHANGE_SUCCESS.name, cid=credentials_id)
		if entry is not None:
			result['spct'] = entry['_c']

		entry = await self._get_latest_entry(AuditCode.PASSWORD_CHANGE_FAILED.name, cid=credentials_id)
		if entry is not None:
			result['fpct'] = entry['_c']

		return result


	async def get_last_authorized_tenants(self, credentials_id: str):
		entry = await self._get_latest_entry(
			AuditCode.AUTHORIZE_SUCCESS.name,
			cid=credentials_id,
			tenants={"$ne": None}
		)
		if entry is not None:
			return entry["tenants"]
		else:
			return None
