import logging
from typing import Optional

import asab.storage.exceptions

import pymongo

from passlib.hash import bcrypt
from .mongodb import MongoDBCredentialsProvider

from ...events import EventTypes

#

L = logging.getLogger(__name__)

#


class M2MMongoDBCredentialsService(asab.Service):

	def __init__(self, app, service_name="seacatauth.credentials.m2m"):
		super().__init__(app, service_name)

	def create_provider(self, provider_id, config_section_name):
		return M2MMongoDBCredentialsProvider(self.App, provider_id, config_section_name)


class M2MMongoDBCredentialsProvider(MongoDBCredentialsProvider):
	"""
	Machine credentials provider with MongoDB backend.

	Machine credentials are meant solely for machine-to-machine communication (API access)
	and cannot be used for web UI login.
	No registration.
	No ident (basic auth must be exact username match)

	Available authn factors:
	basic_auth (username+password)
	api_token
	certificate
	"""
	# TODO: Implement API key authn
	# TODO: Implement certificate authn

	Type = "m2m"

	ConfigDefaults = {
		"credentials_collection": "mc",
		"tenants": "no",
		"creation_features": "username password",
		"ident_fields": "username"
	}

	def __init__(self, app, provider_id, config_section_name):
		super().__init__(app, provider_id, config_section_name)
		self.RegistrationFeatures = None

	async def initialize(self):
		coll = await self.MongoDBStorageService.collection(self.CredentialsCollection)

		try:
			await coll.create_index(
				[
					("username", pymongo.ASCENDING),
				],
				unique=True
			)
		except Exception as e:
			L.warning("{}; fix it and restart the app".format(e))

	async def create(self, credentials: dict) -> Optional[str]:
		value = credentials.get("username")
		if value is not None and len(value) > 0:
			obj_id = self._create_credential_id(value)
		else:
			raise ValueError("Cannot determine user ID")

		u = self.MongoDBStorageService.upsertor(self.CredentialsCollection, obj_id)

		u.set("username", credentials["username"])
		u.set("__password", bcrypt.hash(credentials["password"].encode("utf-8")))

		credentials_id = await u.execute(event_type=EventTypes.M2M_CREDENTIALS_CREATED)

		L.log(asab.LOG_NOTICE, "Credentials created", struct_data={
			"provider_id": self.ProviderID,
			"cid": credentials_id
		})

		return "{}{}".format(self.Prefix, credentials_id)


	async def get_login_descriptors(self, credentials_id):
		return None
