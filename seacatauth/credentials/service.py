import collections
import logging
import asyncio
import re

import asab
import asab.storage.exceptions
import asab.exceptions
import typing

from .policy import CredentialsPolicy
from .providers.abc import CredentialsProviderABC, EditableCredentialsProviderABC
from .. import AuditLogger, generic, exceptions
from ..session import SessionAdapter

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

		# Iterate over config and create all providers
		relevant_sections = [s for s in asab.Config.sections() if s.startswith("seacatauth:credentials:")]
		providers = []
		for section in relevant_sections:
			_, creds, provider_type, provider_name = section.rsplit(":", 3)

			svc_name = "seacatauth.{}.{}".format(creds, provider_type)

			# Ensure that providers are loaded when they are needed
			if svc_name not in app.Services:
				if svc_name == "seacatauth.credentials.htpasswd":
					from .providers.htpasswd import HTPasswdCredentialsService
					HTPasswdCredentialsService(app)
				elif svc_name == "seacatauth.credentials.dict":
					from .providers.dictionary import DictCredentialsService
					DictCredentialsService(app)
				elif svc_name == "seacatauth.credentials.mongodb":
					from .providers.mongodb import MongoDBCredentialsService
					MongoDBCredentialsService(app)
				elif svc_name == "seacatauth.credentials.m2m":
					from .providers.m2m_mongodb import M2MMongoDBCredentialsService
					M2MMongoDBCredentialsService(app)
				elif svc_name == "seacatauth.credentials.ldap":
					from .providers.ldap import LDAPCredentialsService
					LDAPCredentialsService(app)
				elif svc_name == "seacatauth.credentials.elasticsearch":
					from .providers.elasticsearch import ElasticSearchCredentialsService
					ElasticSearchCredentialsService(app)
				elif svc_name == "seacatauth.credentials.mysql":
					from .providers.mysql import MySQLCredentialsService
					MySQLCredentialsService(app)
				elif svc_name == "seacatauth.credentials.xmongodb":
					from .providers.xmongodb import XMongoDBCredentialsService
					XMongoDBCredentialsService(app)

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
			self.register_provider(provider)

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


	def register_provider(self, credentials_provider):
		self.CredentialProviders[credentials_provider.ProviderID] = credentials_provider


	async def locate(self, ident: str, stop_at_first: bool = False, login_dict: dict = None):
		'''
		Locate credentials based on the vague 'ident', which could be the username, password, phone number etc.
		'''
		ident = ident.strip()
		credentials_ids = []
		pending = [
			asyncio.create_task(provider.locate(ident, self.IdentFields, login_dict))
			for provider in self.CredentialProviders.values()]
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

				assert (isinstance(result, str))

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

	async def iterate(self):
		"""
		This iterates over all providers and combines their results
		"""
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


	async def list(self, session: SessionAdapter, search_params: generic.SearchParams, global_search: bool = False):
		"""
		List credentials that are members of currently authorized tenants.
		Global_search lists all credentials, regardless of tenants, but this requires superuser authorization.
		"""
		if len(search_params.AdvancedFilter) > 1:
			raise asab.exceptions.ValidationError("No more than one advanced filter at a time is supported.")

		if global_search and not session.has_global_resource_access(resource_id="authz:tenant:access"):
			raise exceptions.AccessDeniedError(
				"Not authorized to list credentials across all tenants", subject=session.Credentials.Id)

		authorized_tenants = [tenant for tenant in session.Authorization.Authz if tenant != "*"]

		# Authorize searched tenants
		if "tenant" in search_params.AdvancedFilter:
			# Search only requested tenant
			tenant_id = search_params.AdvancedFilter["tenant"]
			# Check authorization
			if not global_search and tenant_id not in authorized_tenants:
				raise exceptions.AccessDeniedError(
					"Not authorized to access tenant members",
					subject=session.Credentials.Id,
					resource={"tenant_id": tenant_id}
				)
			searched_tenants = [tenant_id]
		elif global_search:
			# Search all credentials, ignore tenants
			searched_tenants = None
		else:
			# Search currently authorized tenants
			searched_tenants = authorized_tenants

		if "role" in search_params.AdvancedFilter:
			# Authorize searched roles
			role_id = search_params.AdvancedFilter["role"]
			tenant_id = role_id.split("/")[0]
			# Check authorization
			if not global_search and tenant_id not in authorized_tenants:
				raise exceptions.AccessDeniedError(
					"Not authorized to access tenant members",
					subject=session.Credentials.Id,
					resource={"tenant_id": tenant_id}
				)
			if not session.has_resource_access(tenant_id, "seacat:role:access"):
				raise exceptions.AccessDeniedError(
					"Not authorized to access role details",
					subject=session.Credentials.Id,
					resource={"role_id": role_id}
				)
			searched_roles = [role_id]
		else:
			# Do not filter by roles
			searched_roles = None

		# Get role or tenant assignment objects
		if searched_roles:
			role_svc = self.App.get_service("seacatauth.RoleService")
			assignments = await role_svc.list_role_assignments(
				role_id=searched_roles, page=search_params.Page, limit=search_params.ItemsPerPage)
		elif searched_tenants:
			tenant_svc = self.App.get_service("seacatauth.TenantService")
			provider = tenant_svc.get_provider()
			assignments = await provider.list_tenant_assignments(
				searched_tenants, search_params.Page, search_params.ItemsPerPage)
		else:
			assignments = None

		if assignments is not None:
			if assignments["count"] == 0:
				return {"count": 0, "data": []}

			credentials = []
			total_count = assignments["count"]

			for assignment in assignments["data"]:
				cid = assignment["c"]
				_, provider_id, _ = cid.split(":", 2)
				provider = self.CredentialProviders[provider_id]
				try:
					credentials.append(await provider.get(cid))
				except KeyError:
					L.warning("Found an assignment of nonexisting credentials", struct_data={
						"cid": cid,
						"role_id": assignment.get("r"),
						"tenant_id": assignment.get("t"),
					})

			return {
				"data": credentials,
				"count": total_count,
			}

		# Search without external filters
		return await self._list(search_params)


	async def _list(self, search_params: generic.SearchParams):
		"""
		List credentials
		"""
		provider_stack = []
		total_count = 0  # If -1, then total count cannot be determined
		for provider in self.CredentialProviders.values():
			try:
				count = await provider.count(filtr=search_params.SimpleFilter)
			except Exception as e:
				L.exception("Exception when getting count from a credentials provider: {}".format(e))
				continue

			provider_stack.append((count, provider))
			if count >= 0 and total_count >= 0:
				total_count += count
			else:
				total_count = -1

		credentials = []
		offset = search_params.Page * search_params.ItemsPerPage
		remaining_items = search_params.ItemsPerPage
		for count, provider in provider_stack:
			if count >= 0:
				if offset > count:
					# The offset is beyond the count of the provider, skip to the next one
					offset -= count
					continue

				async for credobj in provider.iterate(
					offset=offset, limit=remaining_items, filtr=search_params.SimpleFilter
				):
					credentials.append(credobj)
					remaining_items -= 1

				if remaining_items <= 0:
					break

				offset = 0

			else:
				# TODO: Uncountable branch
				L.error("Not implemented: Uncountable branch.", struct_data={"provider_id": provider.ProviderID})
				continue

		return {
			"data": credentials,
			"count": total_count,
		}


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
		service = self.App.get_service("seacatauth.credentials.dict")
		if service is None:
			from .providers.dictionary import DictCredentialsService
			service = DictCredentialsService(self.App)
		provider = service.create_provider(provider_id, None)
		self.register_provider(provider)


	async def create_credentials(self, provider_id: str, credentials_data: dict, session: SessionAdapter = None):
		# Record the requester's ID for logging purposes
		agent_cid = session.Credentials.Id if session is not None else None

		# Get provider
		provider = self.CredentialProviders[provider_id]
		if not isinstance(provider, EditableCredentialsProviderABC):
			L.error(
				"Cannot create credentials: Provider is read-only", struct_data={
					"provider_id": provider.ProviderID,
					"by": agent_cid,
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
			L.error("Creation failed: Data does not comply with 'create' policy", struct_data={
				"provider_id": provider.ProviderID,
				"by": agent_cid,
			})
			return {
				"status": "FAILED",
				"message": "Credentials data does not comply with creation policy",
			}

		# Create in provider
		try:
			credentials_id = await provider.create(validated_data)
		except asab.storage.exceptions.DuplicateError as e:
			L.error("Cannot create credentials: {}".format(e))
			return {
				"status": "FAILED",
				"message": "Cannot create credentials: Duplicate key",
				"conflict": e.KeyValue
			}
		except Exception as e:
			L.error("Cannot create credentials: {}".format(e))
			return {
				"status": "FAILED",
				"message": "Cannot create credentials",
			}

		AuditLogger.log(asab.LOG_NOTICE, "Credentials created", struct_data={
			"cid": credentials_id,
			"by_cid": agent_cid,
		})
		self.App.PubSub.publish("Credentials.created!", credentials_id=credentials_id)

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
		agent_cid = session.Credentials.Id if session is not None else None

		# Disallow sensitive field updates
		for key in update_dict:
			if key == "password" or key.startswith("_"):
				L.error("Update failed: Cannot update sensitive fields", struct_data={
					"cid": credentials_id,
					"field": key,
					"by": agent_cid,
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
				"by": agent_cid,
			})
			return {
				"status": "FAILED",
				"message": "Provider does not support editing",
			}

		# Custom data is not validated with policy
		# TODO: Configurable policy/schema for custom data
		custom_data = update_dict.pop("data", None)

		# Check credentials policy
		if session is not None:
			authz = session.Authorization.Authz
		else:
			authz = None
		validated_data = self.Policy.validate_update_data(update_dict, authz)
		if validated_data is None:
			L.error("Update failed: Data does not comply with update policy", struct_data={
				"provider_id": provider.ProviderID,
				"cid": credentials_id,
				"by": agent_cid,
			})
			return {
				"status": "FAILED",
				"message": "Data does not comply with update policy",
			}

		# Validate that at least phone or email will be specified after update
		current_dict = await provider.get(credentials_id)

		if current_dict.get("__registration") is not None and update_dict.get("suspended") is False:
			raise asab.exceptions.ValidationError(
				"Cannot unsuspend credential whose registration has not been completed.")

		if "email" in update_dict:
			email_specified = update_dict["email"] is not None
		elif "email" not in current_dict or current_dict["email"] is None:
			email_specified = False
		else:
			email_specified = True

		if "phone" in update_dict:
			phone_specified = update_dict["phone"] is not None
		elif "phone" not in current_dict or current_dict["phone"] is None:
			phone_specified = False
		else:
			phone_specified = True

		if (not email_specified) and (not phone_specified):
			L.error("Update failed: Phone and email cannot both be empty", struct_data={
				"provider_id": provider.ProviderID,
				"cid": credentials_id,
				"by": agent_cid,
			})
			return {
				"status": "FAILED",
				"message": "Phone and email cannot both be empty",
			}

		if custom_data is not None:
			validated_data["data"] = custom_data

		# Update in provider
		await provider.update(credentials_id, validated_data)

		AuditLogger.log(asab.LOG_NOTICE, "Credentials updated", struct_data={
			"cid": credentials_id,
			"by_cid": agent_cid,
			"attributes": list(validated_data.keys()),
		})
		self.App.PubSub.publish("Credentials.updated!", credentials_id=credentials_id)

		return {"status": "OK"}


	async def delete_credentials(self, credentials_id: str, agent_cid: str = None):
		# Get provider
		provider = self.get_provider(credentials_id)
		if not isinstance(provider, EditableCredentialsProviderABC):
			L.error(
				"Cannot delete credentials: Provider is read-only", struct_data={
					"provider_id": provider.ProviderID,
					"agent_cid": agent_cid,
				}
			)
			return {
				"status": "FAILED",
				"message": "Provider does not support credentials deletion",
			}

		# Delete user sessions
		session_svc = self.App.get_service("seacatauth.SessionService")
		await session_svc.delete_sessions_by_credentials_id(credentials_id)

		# Unassign tenants
		# This also automatically unassigns roles
		tenant_svc = self.App.get_service("seacatauth.TenantService")
		tenants = await tenant_svc.get_tenants(credentials_id)
		for tenant in tenants:
			await tenant_svc.unassign_tenant(credentials_id, tenant)

		# Unassign global roles
		role_svc = self.App.get_service("seacatauth.RoleService")
		await role_svc.set_roles(
			credentials_id,
			roles=[],
			include_global=True
		)

		# Delete credentials in provider
		result = await provider.delete(credentials_id)

		AuditLogger.log(asab.LOG_NOTICE, "Credentials deleted", struct_data={
			"cid": credentials_id, "by_cid": agent_cid})

		self.App.PubSub.publish("Credentials.deleted!", credentials_id=credentials_id)

		return {
			"status": result,
			"credentials_id": credentials_id,
		}


	def get_provider_info(self, provider_id):
		"""
		Combine provider capabilities with credentials policy
		"""
		provider = self.CredentialProviders[provider_id]
		info = provider.get_info()

		if not isinstance(provider, EditableCredentialsProviderABC):
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
		if provider.RegistrationEnabled and len(self.Policy.RegistrationPolicy) > 0:
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
