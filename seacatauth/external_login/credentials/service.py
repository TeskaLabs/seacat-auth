import logging
import aiohttp
import asab
import asab.web.rest
import pymongo

from ... import exceptions
from ...models.const import ResourceId
from ..exceptions import (
	PairingExternalAccountError,
	ExternalAccountNotFoundError,
)


L = logging.getLogger(__name__)


class ExternalCredentialsService(asab.Service):
	"""
	Manages external credentials linked to internal credentials.
	"""

	ExternalCredentialsCollection = "el"

	def __init__(self, app, service_name="seacatauth.ExternalCredentialsService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.CredentialsService = None
		self.RegistrationService = None
		self.ExternalAuthenticationService = None

		self.RegistrationWebhookUri = asab.Config.get(
			"seacatauth:external_login", "registration_webhook_uri").rstrip("/")


	async def initialize(self, app):
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.RegistrationService = app.get_service("seacatauth.RegistrationService")
		self.ExternalAuthenticationService = app.get_service("seacatauth.ExternalAuthenticationService")

		coll = await self.StorageService.collection(self.ExternalCredentialsCollection)
		await coll.create_index([("cid", pymongo.ASCENDING)])


	async def sign_up_ext_credentials(
		self,
		provider_type: str,
		user_info: dict,
		authorization_data: dict,
	) -> str:
		"""
		Register new credentials and pair them with the external account.

		Args:
			provider_type: The type of the external identity provider (e.g., "google", "facebook").
			user_info: A dictionary containing user information obtained from the external identity provider.
			authorization_data: A dictionary containing authorization data (e.g., tokens) obtained from the external identity provider.

		Returns:
			The ID of the newly created credentials.

		Raises:
			SignupWithExternalAccountError: If sign-up fails due to various reasons (e.g., account already exists,
				registration disabled).
		"""
		if self.RegistrationWebhookUri:
			# Register external user via webhook
			authorization_data_safe = {
				k: v
				for k, v in authorization_data.items()
				if k != "code"
			}
			credentials_id = await self._create_credentials_via_webhook(
				provider_type, user_info, authorization_data_safe)
		else:
			ext_provider = self.ExternalAuthenticationService.get_provider(provider_type)
			cred_data = {
				"username": user_info.get("preferred_username"),
				"email": user_info.get("email"),
				"phone": user_info.get("phone_number"),
			}
			cp = getattr(self.RegistrationService, "CredentialProvider", None)
			if cp is None:
				raise exceptions.CredentialsRegistrationError(
					"Registration is disabled: No credential provider configured", credentials=cred_data)
			if not (self.RegistrationService.SelfRegistrationEnabled or ext_provider.trust_all_credentials()):
				raise exceptions.CredentialsRegistrationError("Registration is disabled", credentials=cred_data)
			try:
				credentials_id = await cp.create(cred_data)
			except Exception as e:
				raise exceptions.CredentialsRegistrationError("Failed to register credentials", credentials=cred_data) from e

		assert credentials_id

		try:
			await self.create_ext_credentials(credentials_id, provider_type, user_info)
		except asab.exceptions.Conflict as e:
			L.log(asab.LOG_NOTICE, "Cannot pair external account: Already paired.", struct_data={
				"cid": credentials_id,
				"provider": provider_type,
				"sub": user_info.get("sub"),
			})
			raise PairingExternalAccountError(
				"External account already paired.",
				subject_id=user_info.get("sub"),
				credentials_id=credentials_id,
				provider_type=provider_type,
			) from e

		return credentials_id


	async def create_ext_credentials(self, credentials_id: str, provider_type: str, user_info: dict) -> str:
		"""
		Create and store a new external credentials linked to an internal credentials ID.

		Args:
			credentials_id: The ID of the credentials to link the external account to.
			provider_type: The type of the external identity provider (e.g., "google", "facebook").
			user_info: A dictionary containing user information obtained from the external identity provider.

		Returns:
			The ID of the newly created external credentials.
		"""
		ensure_edit_permissions(credentials_id)

		sub = str(user_info["sub"])
		upsertor = self.StorageService.upsertor(
			self.ExternalCredentialsCollection,
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
			external_account_id = await upsertor.execute()
		except asab.storage.exceptions.DuplicateError as e:
			raise asab.exceptions.Conflict("External account already registered") from e
		L.log(asab.LOG_NOTICE, "External login account added", struct_data={
			"id": external_account_id,
			"cid": credentials_id,
		})
		return external_account_id


	async def get_ext_credentials(self, provider_type: str, subject_id: str) -> dict:
		"""
		Retrieve external credentials by provider type and subject ID.

		Args:
			provider_type: The type of the external identity provider (e.g., "google", "facebook").
			subject_id: The subject ID of the user in the external identity provider.

		Returns:
			A dictionary containing the external credentials information.
		"""
		ext_creds_id = _make_id(provider_type, subject_id)
		try:
			ext_credentials = await self.StorageService.get(self.ExternalCredentialsCollection, ext_creds_id)
		except KeyError:
			raise ExternalAccountNotFoundError(provider_type, subject_id)

		ext_credentials = _add_back_compat_fields(ext_credentials)

		ensure_access_permissions(ext_credentials["cid"])

		return ext_credentials


	async def list_ext_credentials(self, credentials_id: str) -> list:
		"""
		List all external credentials linked to a given internal credentials ID.

		Args:
			credentials_id: The ID of the credentials whose linked external accounts are to be listed.

		Returns:
			A list of dictionaries, each containing information about a linked external credentials.
		"""
		ensure_access_permissions(credentials_id)

		collection = self.StorageService.Database[self.ExternalCredentialsCollection]
		query = {"cid": credentials_id}
		cursor = collection.find(query)
		cursor.sort("_c", -1)

		ext_credentials = []
		async for cred in cursor:
			ext_credentials.append(_add_back_compat_fields(cred))

		return ext_credentials


	async def update_ext_credentials(self, provider_type: str, subject_id: str, **kwargs):
		raise NotImplementedError()


	async def delete_ext_credentials(self, provider_type: str, subject_id: str):
		"""
		Delete external credentials by provider type and subject ID.

		Args:
			provider_type: The type of the external identity provider (e.g., "google", "facebook").
			subject_id: The subject ID of the user in the external identity provider.
		"""
		ext_creds_id = _make_id(provider_type, subject_id)
		try:
			ext_credentials = await self.StorageService.get(self.ExternalCredentialsCollection, ext_creds_id)
		except KeyError:
			raise ExternalAccountNotFoundError(provider_type, subject_id)

		ensure_edit_permissions(ext_credentials["cid"])

		return await self.StorageService.delete(self.ExternalCredentialsCollection, ext_creds_id)


	async def _create_credentials_via_webhook(
		self,
		provider_type: str,
		user_info: dict,
		authorization_data: dict,
	) -> str:
		"""
		Send external login user_info to webhook for registration.
		If the server responds with 200 and the JSON body contains 'cid' of the registered credentials,
		create an entry in the external login collection and return the credential ID.
		Otherwise, raise error.
		"""
		assert self.RegistrationWebhookUri is not None

		request_data = {
			"provider_type": provider_type,
			"user_info": user_info,
			"authorization_response": authorization_data,
		}

		async with aiohttp.ClientSession() as session:
			async with session.post(self.RegistrationWebhookUri, json=request_data) as resp:
				if resp.status not in frozenset([200, 201]):
					text = await resp.text()
					L.error("Webhook responded with error", struct_data={
						"status": resp.status, "text": text, "url": self.RegistrationWebhookUri})
					raise exceptions.CredentialsRegistrationError("Webhook responded with error")
				response_data = await resp.json()

		credentials_id = response_data.get("credentials_id")
		if not credentials_id:
			L.error("Webhook response does not contain required 'credentials_id' field", struct_data={
				"response_data": response_data})
			raise exceptions.CredentialsRegistrationError("Unexpected webhook response")

		# Test if the ID is reachable
		try:
			await self.CredentialsService.get(credentials_id)
		except KeyError:
			L.error("Returned credential ID not found", struct_data={"response_data": response_data})
			raise exceptions.CredentialsRegistrationError("Returned credentials ID not found")

		return credentials_id


def _make_id(provider_type: str, subject_id: str):
	return "{} {}".format(provider_type, subject_id)


def _add_back_compat_fields(account: dict):
	if "e" in account and "email" not in account:
		account["email"] = account["e"]
	if "s" in account and "sub" not in account:
		account["sub"] = account["s"]
	if "t" in account and "type" not in account:
		account["type"] = account["t"]
	return account


def ensure_access_permissions(credentials_id: str):
	authz = asab.contextvars.Authz.get()
	if authz.CredentialsId != credentials_id:
		authz.require_resource_access(ResourceId.CREDENTIALS_ACCESS)


def ensure_edit_permissions(credentials_id: str):
	authz = asab.contextvars.Authz.get()
	if authz.CredentialsId != credentials_id:
		authz.require_resource_access(ResourceId.CREDENTIALS_EDIT)
