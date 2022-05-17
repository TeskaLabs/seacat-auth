import collections
import logging
import asyncio
import re

import asab
import typing

from seacatauth.credentials.policy import CredentialsPolicy
from seacatauth.credentials.providers.abc import CredentialsProviderABC, EditableCredentialsProviderABC
from seacatauth.session import SessionAdapter

#

L = logging.getLogger(__name__)

#

LOGIN_DESCRIPTOR_FAKE = [{
	'id': 'default',
	'label': 'Use recommended login.',
	'factors': [{
		'id': 'password',
		'type': 'password'
	}],
}]


class CredentialsService(asab.Service):
	def __init__(self, app, service_name='seacatauth.CredentialsService', tenant_service=None):
		super().__init__(app, service_name)
		self.CredentialProviders: typing.Dict[str, CredentialsProviderABC] = collections.OrderedDict()
		self.LoginDescriptorFake = LOGIN_DESCRIPTOR_FAKE

		rbac_svc = app.get_service("seacatauth.RBACService")
		cred_policy_file = asab.Config.get("seacatauth:credentials", "policy_file")
		self.Policy = CredentialsPolicy(rbac_svc, cred_policy_file)

		self.IdentFields = self._prepare_ident_fields(asab.Config.get("seacatauth:credentials", "ident_fields"))

		# from .google.handler import GoogleOAuth2Handler
		# self.GoogleOAuth2Handler = GoogleOAuth2Handler(app)

		# Iterate over config and create all providers
		relevant_sections = [s for s in asab.Config.sections() if s.startswith("seacatauth:credentials:")]
		providers = []
		for section in relevant_sections:
			_, creds, provider_type, provider_name = section.rsplit(":", 3)

			svc_name = "seacatauth.{}.{}".format(creds, provider_type)

			# Ensure that providers are loaded when they are needed
			if svc_name not in app.Services:
				if svc_name == 'seacatauth.credentials.htpasswd':
					from .providers.htpasswd import HTPasswdCredentialsService
					HTPasswdCredentialsService(app)
				elif svc_name == 'seacatauth.credentials.dict':
					from .providers.dictionary import DictCredentialsService
					DictCredentialsService(app)
				elif svc_name == 'seacatauth.credentials.mongodb':
					from .providers.mongodb import MongoDBCredentialsService
					MongoDBCredentialsService(app)
				elif svc_name == 'seacatauth.credentials.m2m':
					from .providers.m2m_mongodb import M2MMongoDBCredentialsService
					M2MMongoDBCredentialsService(app)
				elif svc_name == 'seacatauth.credentials.ldap':
					from .providers.ldap import LDAPCredentialsService
					LDAPCredentialsService(app)
				elif svc_name == 'seacatauth.credentials.elasticsearch':
					from .providers.elasticsearch import ElasticSearchCredentialsService
					ElasticSearchCredentialsService(app)

			service = app.get_service(svc_name)

			provider = service.create_provider(provider_name, section)
			providers.append((provider.Order, provider))

			if tenant_service is not None:
				if not provider.Config.getboolean('tenants'):
					continue
				tenant_service.create_provider(provider_name, section)

		# Sort providers by their configured order
		providers.sort(key=lambda item: item[0])
		for order, provider in providers:
			self.register(provider)


		# Metrics
		self.MetricsService = app.get_service('asab.MetricsService')
		self.TaskService = app.get_service('asab.TaskService')
		self.Providers = providers
		self.CredentialsGauge = self.MetricsService.create_gauge(
			"credentials",
			tags={"help": "Counts credentials per provider."},
			init_values={provider.ProviderID: 0 for _, provider in self.Providers}
		)
		app.PubSub.subscribe("Application.tick/10!", self._on_tick_metric)


	def _on_tick_metric(self, event_name):
		self.TaskService.schedule(self._metrics_task())


	async def _metrics_task(self):
		for _, provider in self.Providers:
			total = await provider.count()
			if total == -1:
				continue
			else:
				self.CredentialsGauge.set(provider.ProviderID, total)


	def _prepare_ident_fields(self, ident_config):
		ident_fields = {}
		for field in re.split(r"\s+", ident_config):
			if ":" in field:
				field_name, modifier = field.split(":")
			else:
				field_name = field
				modifier = None
			ident_fields[field_name] = modifier
		return ident_fields


	def register(self, credentials_provider):
		self.CredentialProviders[credentials_provider.ProviderID] = credentials_provider


	async def locate(self, ident: str, stop_at_first: bool = False):
		'''
		Locate credentials based on the vague 'ident', which could be the username, password, phone number etc.
		'''
		ident = ident.strip()
		credentials_ids = []
		pending = [provider.locate(ident, self.IdentFields) for provider in self.CredentialProviders.values()]
		while len(pending) > 0:
			done, pending = await asyncio.wait(pending)
			for task in done:

				try:
					result = task.result()
				except Exception as e:
					L.exception("Exception when locating credentials in a provider: {}".format(e))
					continue

				if result is None:
					continue

				assert(isinstance(result, str))

				if stop_at_first:
					for f in pending:
						f.cancel()
					return result

				credentials_ids.append(result)

		if stop_at_first:
			return None
		return credentials_ids


	async def get_by(self, key: str, value):
		"""
		Get credentials by an indexed key
		"""
		credentials = None
		for provider in self.CredentialProviders.values():
			credentials = await provider.get_by(key, value)
			if credentials is not None:
				break
		return credentials

	async def get_by_external_login_sub(self, login_provider: str, sub_id: str):
		"""
		Get credentials by an indexed key
		"""
		credentials = None
		for provider in self.CredentialProviders.values():
			credentials = await provider.get_by_external_login_sub(login_provider, sub_id)
			if credentials is not None:
				break
		return credentials

	async def iterate(self):
		'''
		This iterates over all providers and combines their results
		'''
		pending = [provider.iterate() for provider in self.CredentialProviders.values()]
		pending_tasks = {
			asyncio.ensure_future(g.__anext__()): g for g in pending
		}
		while len(pending_tasks) > 0:
			done, _ = await asyncio.wait(pending_tasks.keys(), return_when="FIRST_COMPLETED")
			for d in done:
				dg = pending_tasks.pop(d)

				try:
					r = await d
				except StopAsyncIteration:
					continue

				pending_tasks[asyncio.ensure_future(dg.__anext__())] = dg
				yield r


	def get_provider(self, credentials_id):
		try:
			provider_type, provider_id, credentials_subid = credentials_id.split(':', 3)
		except ValueError:
			raise KeyError("Provider not found because credentials_id format is incorrect.")
		provider = self.CredentialProviders.get(provider_id)
		if provider is None:
			raise KeyError("Provider not found")
		if provider.Type != provider_type:
			raise KeyError("Provider type doesn't match '{}' != '{}'".format(provider.Type, provider_type))
		return provider


	async def detail(self, credentials_id) -> dict:
		'''
		Find detail of credentials for a credentials_id.
		'''
		# TODO: this is obsoleted and should be replaced by get() method
		return await self.get(credentials_id)


	async def get(self, credentials_id, include=None) -> dict:
		'''
		Find detail of credentials for a credentials_id.
		'''
		provider = self.get_provider(credentials_id)
		return await provider.get(credentials_id, include=include)


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		try:
			provider = self.get_provider(credentials_id)
			return await provider.authenticate(credentials_id, credentials)
		except KeyError:
			return False


	async def register_credentials(self, register_info: dict):
		'''
		This is an anonymous user request to register (create) new credentials
		'''

		# Locate provider
		provider = None
		for p in self.CredentialProviders.values():
			if not p.Config.getboolean('register'):
				continue
			provider = p
			if provider is not None:
				break

		if provider is None:
			L.warning("Registration of new credentials failed")
			return None

		return await provider.register(register_info)


	async def get_login_descriptors(self, credentials_id) -> list:
		# NOTE: this method is not used anywhere in SCA at the moment
		# TODO: refactor this into get_login_preferences
		'''
		Find detail of credentials for a credentials_id.
		'''
		if credentials_id == "":
			return self.LoginDescriptorFake
		provider = self.get_provider(credentials_id)
		return await provider.get_login_descriptors(credentials_id)


	def create_dict_provider(self, provider_id):
		from .providers.dictionary import DictCredentialsService
		DictCredentialsService(self.App)
		service = self.App.get_service("seacatauth.credentials.dict")
		provider = service.create_provider(provider_id, None)
		self.register(provider)


	async def create_credentials(self, provider_id: str, credentials_data: dict, session: SessionAdapter = None):
		# Record the requester's ID for logging purposes
		agent_cid = session.Credentials.id if session is not None else None

		# Get provider
		provider = self.CredentialProviders[provider_id]
		if not isinstance(provider, EditableCredentialsProviderABC):
			L.error(
				"Cannot create credentials: Provider is read-only", struct_data={
					"provider_id": provider.ProviderID,
					"agent_cid": agent_cid,
				}
			)
			return {
				"status": "FAILED",
				"message": "Provider does not support credentials creation",
			}

		# Only update fields allowed by creation policy
		if provider.Type == "m2m":
			validated_data = self.Policy.validate_m2m_creation_data(credentials_data)
		else:
			validated_data = self.Policy.validate_creation_data(credentials_data)
		if validated_data is None:
			L.error("Update failed: Data does not comply with update policy", struct_data={
				"provider_id": provider.ProviderID,
				"agent_cid": agent_cid,
			})
			return {
				"status": "FAILED",
				"message": "Credentials data does not comply with creation policy",
			}

		# Create in provider
		try:
			credentials_id = await provider.create(validated_data)
		except Exception as e:
			L.error("Cannot create credentials: {}".format(e))
			return {
				"status": "FAILED",
				"message": "Cannot create credentials",
			}

		L.log(asab.LOG_NOTICE, "Credentials successfully created", struct_data={
			"provider_id": provider.ProviderID,
			"cid": credentials_id,
			"agent_cid": agent_cid,
		})
		return {
			"status": "OK",
			"credentials_id": credentials_id,
		}

	# TODO: Implement editing for M2M credentials
	async def update_credentials(self, credentials_id: str, update_dict: dict, session: SessionAdapter = None):
		"""
		Validate the input data in the update dict according to active policies
		and update credentials in the respective provider.

		NOTE:
			This method is designed for API purposes.
			For app-internal purposes (password change etc.), directly use the update() method
			in the respective credentials provider
		"""
		# Record the requester's ID for logging purposes
		agent_cid = session.Credentials.id if session is not None else None

		# Disallow sensitive field updates
		for key in update_dict:
			if key == "password" or key.startswith("_"):
				L.error("Update failed: Cannot update sensitive fields", struct_data={
					"cid": credentials_id,
					"field": key,
					"agent_cid": agent_cid,
				})
				return {
					"status": "FAILED",
					"message": "Data does not comply with update policy",
				}

		# Get provider
		provider = self.get_provider(credentials_id)
		if (
			not isinstance(provider, EditableCredentialsProviderABC)
			or provider.Type == "m2m"  # M2M credentials do not support editing for now
		):
			L.error("Update failed: Provider does not support editing", struct_data={
				"provider_id": provider.ProviderID,
				"cid": credentials_id,
				"agent_cid": agent_cid,
			})
			return {
				"status": "FAILED",
				"message": "Provider does not support editing",
			}

		# Check credentials policy
		if session is not None:
			authz = session.Authorization.authz
		else:
			authz = None
		validated_data = self.Policy.validate_update_data(update_dict, authz)
		if validated_data is None:
			L.error("Update failed: Data does not comply with update policy", struct_data={
				"provider_id": provider.ProviderID,
				"cid": credentials_id,
				"agent_cid": agent_cid,
			})
			return {
				"status": "FAILED",
				"message": "Data does not comply with update policy",
			}

		# Update in provider
		result = await provider.update(credentials_id, validated_data)

		if result == "OK":
			L.log(asab.LOG_NOTICE, "Credentials successfully updated", struct_data={
				"cid": credentials_id,
				"agent_cid": agent_cid,
			})

		return {"status": result}


	def get_provider_info(self, provider_id):
		"""
		Combine provider capabilities with credentials policy
		"""
		provider = self.CredentialProviders[provider_id]
		info = provider.get_info()

		if not provider.Editable:
			return info

		# Use different policy for M2M providers
		# TODO: Systematic solution
		if provider.Type == "m2m":
			info["creation"] = [
				{
					"type": field,
					"policy": policy,
				} for field, policy in self.Policy.M2MCreationPolicy.items()
			]
			return info

		# Add edit/creation policies if provider is editable
		if len(self.Policy.RegistrationPolicy) > 0:
			info["registration"] = [
				{
					"type": field,
					"policy": policy,
				} for field, policy in self.Policy.RegistrationPolicy.items()
			]

		if len(self.Policy.CreationPolicy) > 0:
			info["creation"] = [
				{
					"type": field,
					"policy": policy,
				} for field, policy in self.Policy.CreationPolicy.items()
			]
		# Add "passwordlink" field if phone or email is present
		if "email" in self.Policy.CreationPolicy or "phone" in self.Policy.CreationPolicy:
			info["creation"].append({"type": "passwordlink"})

		if len(self.Policy.UpdatePolicy) > 0:
			info["update"] = [
				{
					"type": field,
					"policy": policy,
				} for field, policy in self.Policy.UpdatePolicy.items()
			]

		return info
