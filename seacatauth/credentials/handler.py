import json
import secrets
import logging
import asyncio

import aiohttp
import aiohttp.web

import asab
import asab.web.rest
import asab.web.webcrypto

from ..decorators import access_control
from .schemas import (
	CREATE_CREDENTIALS,
	UPDATE_CREDENTIALS,
	UPDATE_MY_CREDENTIALS,
)

#

L = logging.getLogger(__name__)

#


class CredentialsHandler(object):


	def __init__(self, app, credentials_svc, chpwd_svc):
		self.CredentialsService = credentials_svc
		self.ChangePasswordService = chpwd_svc

		self.SessionService = app.get_service('seacatauth.SessionService')
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.AuditService = app.get_service('seacatauth.AuditService')

		# TODO: refactor Credentials Handler to configurable?
		self.RegistrationEncrypted = asab.Config.getboolean("general", "registration_encrypted")
		self.Registrations = {}

		web_app = app.WebContainer.WebApp

		web_app.router.add_get('/credentials', self.list_credentials)
		web_app.router.add_put('/idents', self.get_idents_from_ids)
		web_app.router.add_put('/usernames', self.get_idents_from_ids)  # TODO: Back compat. Remove once UI adapts to the new endpoint.
		web_app.router.add_get('/locate', self.locate_credentials)
		web_app.router.add_get('/credentials/{credentials_id}', self.get_credentials)

		web_app.router.add_post('/credentials/{provider}', self.create_credentials)
		web_app.router.add_put('/credentials/{credentials_id}', self.update_credentials)
		web_app.router.add_delete('/credentials/{credentials_id}', self.delete_credentials)

		web_app.router.add_put('/public/credentials', self.update_my_credentials)

		# Providers
		web_app.router.add_get('/provider/{provider_id}', self.get_provider_info)
		web_app.router.add_get('/providers', self.list_providers)
		web_app.router.add_get('/public/provider', self.get_my_provider_info)

		web_app.router.add_get('/{tenant}/register/invite', self.create_invite)

		web_app.router.add_get('/public/register', self.register_get)
		web_app.router.add_get('/public/invitation/{register_token}', self.register_with_invite_get)
		web_app.router.add_post('/public/register/{register_token}', self.register_post)

		web_app.router.add_put('/password', self.init_password_change)
		web_app.router.add_get('/public/provider', self.get_my_provider_info)
		web_app.router.add_put('/enforce-factors/{credentials_id}', self.enforce_factors)

		web_app.router.add_put('/public/password-change', self.change_password)
		web_app.router.add_put('/public/password-reset', self.reset_password)

		web_app.router.add_put(r'/public/lost-password', self.lost_password)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_put('/public/credentials', self.update_my_credentials)

		web_app_public.router.add_get('/public/register', self.register_get)
		web_app_public.router.add_get('/public/invitation/{register_token}', self.register_with_invite_get)
		web_app_public.router.add_post('/public/register/{register_token}', self.register_post)

		web_app_public.router.add_put('/password', self.init_password_change)
		web_app_public.router.add_get('/public/provider', self.get_my_provider_info)

		web_app_public.router.add_put('/public/password-change', self.change_password)
		web_app_public.router.add_put('/public/password-reset', self.reset_password)

		web_app_public.router.add_put(r'/public/lost-password', self.lost_password)


	async def list_providers(self, request):
		providers = {}
		for provider_id in self.CredentialsService.CredentialProviders:
			providers[provider_id] = self.CredentialsService.get_provider_info(provider_id)
		return asab.web.rest.json_response(request, providers)


	async def get_provider_info(self, request):
		provider_id = request.match_info["provider_id"]
		data = self.CredentialsService.get_provider_info(provider_id)
		response = {
			"result": "OK",
			**data,  # TODO: Move to response["data"], as in get_my_provider_info()
		}
		return asab.web.rest.json_response(request, response)


	@access_control()
	async def get_my_provider_info(self, request, *, credentials_id):
		provider = self.CredentialsService.get_provider(credentials_id)
		data = self.CredentialsService.get_provider_info(provider.ProviderID)
		response = {
			"result": "OK",
			"data": data,
		}
		return asab.web.rest.json_response(request, response)


	async def locate_credentials(self, request):
		ident = request.query.get('ident')
		stop_at_first = request.query.get('stop_at_first', False)
		credentials_ids = await self.CredentialsService.locate(ident, stop_at_first=stop_at_first)
		return asab.web.rest.json_response(request, {"credentials_ids": credentials_ids})


	async def list_credentials(self, request):
		page = int(request.query.get('p', 1)) - 1
		limit = int(request.query.get('i', 10))

		# Filter mode switches between `default` (username) string filter, `role` match and `tenant` match
		mode = request.query.get("m", "default")
		filtr = request.query.get("f", "")
		if len(filtr) == 0:
			filtr = None

		# Filtering based on IDs obtained form another collection
		if mode in frozenset(["role", "tenant"]):
			if filtr is None:
				L.error("No filter string specified.", struct_data={"mode": mode})
				raise aiohttp.web.HTTPBadRequest()

			# These filters require access to authz:tenant:admin resource
			rbac_svc = self.CredentialsService.App.get_service("seacatauth.RBACService")

			if mode == "role":
				# Check if the user has admin access to the role's tenant
				tenant = filtr.split("/")[0]
				if rbac_svc.has_resource_access(request.Session.Authorization.Authz, tenant, ["authz:tenant:admin"]) != "OK":
					return asab.web.rest.json_response(request, {
						"result": "NOT-AUTHORIZED"
					})
				role_svc = self.CredentialsService.App.get_service("seacatauth.RoleService")
				assignments = await role_svc.list_role_assignments(role_id=filtr, page=page, limit=limit)

			elif mode == "tenant":
				# Check if the user has admin access to the requested tenant
				tenant = filtr
				if rbac_svc.has_resource_access(request.Session.Authorization.Authz, tenant, ["authz:tenant:admin"]) != "OK":
					return asab.web.rest.json_response(request, {
						"result": "NOT-AUTHORIZED"
					})
				tenant_svc = self.CredentialsService.App.get_service("seacatauth.TenantService")
				provider = tenant_svc.get_provider()
				assignments = await provider.list_tenant_assignments(tenant, page, limit)

			if assignments["count"] == 0:
				return asab.web.rest.json_response(request, {
					"result": "OK",
					"count": 0,
					"data": []
				})

			credentials = []
			total_count = assignments["count"]

			# Sort the ids by their respective provider
			for assignment in assignments["data"]:
				cid = assignment["c"]
				_, provider_id, _ = cid.split(":", 2)
				provider = self.CredentialsService.CredentialProviders[provider_id]
				credentials.append(await provider.get(cid))

		# Substring based filtering
		elif mode in frozenset(["", "default"]):
			stack = []
			total_count = 0  # If -1, then total count cannot be determined
			for provider in self.CredentialsService.CredentialProviders.values():
				try:
					count = await provider.count(filtr=filtr)
				except Exception as e:
					L.exception("Exception when getting count from a credentials provider: {}".format(e))
					continue

				stack.append((count, provider))
				if count >= 0 and total_count >= 0:
					total_count += count
				else:
					total_count = -1

			# Scroll to first relevant provider
			offset = page * limit
			credentials = []

			for count, provider in stack:
				if count >= 0:
					if offset > count:
						# The offset is beyond the count of the provider, so let's skip to the next one
						offset -= count
						continue

					async for credobj in provider.iterate(offset=offset, limit=limit, filtr=filtr):
						credentials.append(credobj)
						limit -= 1

					if limit <= 0:
						#  We are done here ...
						break

					# Continue to the beginning of the next provider (zero offset)
					offset = 0

				else:
					# TODO: Uncountable branch
					L.error("Not implemented: Uncountable branch.", struct_data={"provider_id": provider.ProviderID})
					continue

		else:
			L.error("Unsupported filter mode", struct_data={"mode": mode})
			raise aiohttp.web.HTTPBadRequest()

		#  Add brief tenant and role info into credentials list
		for cred in credentials:
			role_svc = self.CredentialsService.App.get_service("seacatauth.RoleService")
			roles = await role_svc.get_roles_by_credentials(cred["_id"])
			tenants = await self.TenantService.get_tenants(cred["_id"])

			tenants = tenants[:5]
			roles = roles[:5]

			cred['tenants'] = tenants
			cred['roles'] = roles

		return asab.web.rest.json_response(request, {
			"result": "OK",
			"data": credentials,
			"count": total_count,
		})


	@asab.web.rest.json_schema_handler({
		"type": "array",
		"items": {
			"type": "string"
		}
	})
	async def get_idents_from_ids(self, request, *, json_data):
		result_data = {}
		failed_ids = []
		for cred_id in json_data:
			try:
				cred_obj = await self.CredentialsService.get(cred_id)
			except KeyError:
				failed_ids.append(cred_id)
				continue
			ident = cred_obj.get("username") \
				or cred_obj.get("email") \
				or cred_obj.get("phone") \
				or cred_id
			result_data[cred_id] = ident

		if len(failed_ids) > 0:
			L.warning("Credentials not found", struct_data={
				"cids": failed_ids
			})
		return asab.web.rest.json_response(request, {
			"result": "OK",
			"data": result_data
		})


	async def get_credentials(self, request):
		credentials_id = request.match_info["credentials_id"]
		_, provider_id, _ = credentials_id.split(':', 2)
		provider = self.CredentialsService.CredentialProviders[provider_id]

		credentials = await provider.get(request.match_info["credentials_id"])

		credentials['_ll'] = await self.AuditService.get_last_logins(credentials_id)

		return asab.web.rest.json_response(request, credentials)


	@asab.web.rest.json_schema_handler(CREATE_CREDENTIALS)
	@access_control("authz:tenant:admin")
	async def create_credentials(self, request, *, json_data):
		"""
		Create new credentials.
		"""
		password_link = json_data.pop("passwordlink", False)

		provider_id = request.match_info["provider"]
		provider = self.CredentialsService.CredentialProviders[provider_id]

		# Create credentials
		result = await self.CredentialsService.create_credentials(provider_id, json_data, request.Session)

		if result["status"] != "OK":
			return asab.web.rest.json_response(request, result, status=400)

		credentials_id = result["credentials_id"]

		if password_link:
			# TODO: Separate password creation from password reset
			crd_svc = self.SessionService.App.get_service("seacatauth.ChangePasswordService")
			await crd_svc.init_password_change(credentials_id, is_new_user=True)

		return asab.web.rest.json_response(request, {
			"status": "OK",
			"_id": credentials_id,
			"_type": provider.Type,
			"_provider_id": provider.ProviderID
		})


	@asab.web.rest.json_schema_handler(UPDATE_CREDENTIALS)
	@access_control("authz:superuser")
	async def update_credentials(self, request, *, json_data):
		"""
		Update credentials.
		"""
		credentials_id = request.match_info["credentials_id"]

		# Update credentials
		result = await self.CredentialsService.update_credentials(credentials_id, json_data, request.Session)

		result["result"] = result["status"]  # TODO: Unify response format

		if result["result"] != "OK":
			return asab.web.rest.json_response(request, result, status=400)

		return asab.web.rest.json_response(request, result)


	@asab.web.rest.json_schema_handler(UPDATE_MY_CREDENTIALS)
	@access_control()
	async def update_my_credentials(self, request, *, json_data, credentials_id):
		"""
		Update user's own credentials.
		"""
		result = await self.CredentialsService.update_credentials(
			credentials_id,
			json_data,
			request.Session,
		)

		result["result"] = result["status"]  # TODO: Unify response format

		if result["status"] != "OK":
			return asab.web.rest.json_response(request, result, status=400)

		return asab.web.rest.json_response(request, result)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"additionalProperties": False,
		"required": ["factors"],
		"properties": {
			"factors": {
				"type": "array",
				"description": "Factors to enforce/reset"
			}
		}
	})
	async def enforce_factors(self, request, *, json_data):
		"""
		Specify authn factors to be enforced from the user
		"""
		credentials_id = request.match_info["credentials_id"]
		provider = self.CredentialsService.get_provider(credentials_id)

		enforce_factors = json_data.get("factors")

		# TODO: Implement and use LoginFactor.can_be_enforced() method
		for factor in enforce_factors:
			if factor not in frozenset(["totp", "smscode", "password"]):
				raise ValueError("Login factor cannot be enforced", {"factor": factor})

		result = await provider.update(credentials_id, {
			"enforce_factors": enforce_factors
		})

		return asab.web.rest.json_response(request, {"result": result})


	@access_control("authz:superuser")
	async def delete_credentials(self, request, *, credentials_id):
		"""
		Delete credentials.
		"""
		agent_cid = credentials_id  # Who called the request
		credentials_id = request.match_info["credentials_id"]  # Who will be deleted
		result = await self.CredentialsService.delete_credentials(credentials_id, agent_cid)
		return asab.web.rest.json_response(request, {"result": result})


	def locate_provider(self, request):
		return self.CredentialsService.CredentialProviders[
			request.match_info["provider"]
		]


	async def register_get(self, request):
		# TODO: Limit a total number of active registration
		# TODO: Limit a number of active registration from a single IP
		register_token = secrets.token_urlsafe()
		key = secrets.token_bytes(256 // 8)
		register_info = {
			'timestamp': self.CredentialsService.App.time(),
			"features": [
				"email",
				"password",
				"tenant",
			]
			# TODO: add an IP from where registration is made (including proxy)
		}
		if self.RegistrationEncrypted:
			register_info['key'] = key

		self.Registrations[register_token] = register_info

		result = {
			"register_token": register_token,
			'features': register_info['features'],
		}

		if self.RegistrationEncrypted:
			result["key"] = asab.web.webcrypto.aes_gcm_generate_key(key),

		return asab.web.rest.json_response(request, result)


	async def register_with_invite_get(self, request):
		# TODO: Limit a total number of active registration
		# TODO: Limit a number of active registration from a single IP
		register_token = request.match_info["register_token"]
		register_info = self.Registrations.get(register_token)
		if register_info is None:
			return aiohttp.web.HTTPBadRequest(reason="Invalid register_token.")

		result = {
			"register_token": register_token,
			'features': register_info['features'],
			'tenant': register_info['tenant'],
		}

		if self.RegistrationEncrypted:
			result['key'] = asab.web.webcrypto.aes_gcm_generate_key(register_info["key"]),

		return asab.web.rest.json_response(request, result)


	async def create_invite(self, request):
		# TODO: Limit a total number of active invites
		# TODO: Limit a number of active registration from a single invites
		tenant = request.match_info["tenant"]

		register_token = secrets.token_urlsafe()
		key = secrets.token_bytes(256 // 8)
		register_info = {
			'timestamp': self.CredentialsService.App.time(),
			'key': key,
			'tenant': tenant,
			"features": [
				"email",
				"password",
			]
			# TODO: add an IP from where invite is made (including proxy)
		}
		self.Registrations[register_token] = register_info
		result = {
			"register_token": register_token,
		}
		return asab.web.rest.json_response(request, result)


	async def register_post(self, request):
		register_token = request.match_info["register_token"]
		register_info = self.Registrations.get(register_token)
		if register_info is None:
			return aiohttp.web.HTTPBadRequest(reason="Invalid register_token.")

		headers = request.headers
		authorization_bytes = bytes(headers.get("Authorization", ""), "ascii")
		register_info['request_authorization'] = authorization_bytes

		req_data = await request.read()

		# decrypt request body
		if self.RegistrationEncrypted:
			req_data = asab.web.webcrypto.aes_gcm_decrypt(
				register_info['key'],
				req_data  # , register_token.encode('ascii')
			)
		try:
			data = json.loads(req_data)
		except json.decoder.JSONDecodeError:
			return aiohttp.web.HTTPBadRequest(reason="Invalid json.")

		# fill register_info
		# TODO: Validations !!!
		register_info['request'] = data
		# TODO: If email has to be confirmed, for that here

		# register
		result = await self.CredentialsService.register_credentials(register_info)
		if result is None:
			return asab.web.rest.json_response(request, {'result': 'FAILED'})
		else:
			self.Registrations.pop(register_token)
			return asab.web.rest.json_response(request, {'result': 'OK'})


	@asab.web.rest.json_schema_handler({
		'type': 'object',
		'required': ['oldpassword', 'newpassword'],
		'properties': {
			'oldpassword': {'type': 'string'},
			'newpassword': {'type': 'string'},
		}
	})
	@access_control()
	async def change_password(self, request, *, json_data):
		"""
		There are three general ways how a password could be changed:
		1) By being logged in and providing old password
		2) Being the superuser and specify the password for an user (TODO: Not implemented yet)
		"""
		result = await self.ChangePasswordService.change_password(
			request.Session,
			json_data.get('oldpassword'),
			json_data.get('newpassword'),
		)

		return asab.web.rest.json_response(request, {'result': result})

	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": [
			"newpassword",
			"pwd_token"  # Password reset token
		],
		"properties": {
			"newpassword": {
				"type": "string"
			},
			"pwd_token": {
				"type": "string",
				"description": "One-time code for password reset"
			},
		}
	})
	async def reset_password(self, request, *, json_data):
		"""
		Set a new password using pwdreset_id obtained in "Lost password" procedure
		"""
		# TODO: this call needs to be encrypted
		result = await self.ChangePasswordService.change_password_by_pwdreset_id(
			json_data.get("pwd_token"),
			json_data.get("newpassword"),
		)

		return asab.web.rest.json_response(request, {"result": result})

	@asab.web.rest.json_schema_handler({
		'type': 'object',
		'required': ['credentials_id'],
		'properties': {
			'credentials_id': {'type': 'string'},
			'expiration': {'type': 'number'},
		}
	})
	@access_control("authz:tenant:admin")
	async def init_password_change(self, request, *, json_data):
		"""
		Directly creates a password reset request. This should be called by admin only.
		For user-initiated password reset use `lost_password` method.
		"""
		result = await self.ChangePasswordService.init_password_change(
			json_data.get('credentials_id'),
			expiration=json_data.get('expiration')
		)
		return asab.web.rest.json_response(request, {'result': result})

	@asab.web.rest.json_schema_handler({
		'type': 'object',
		'required': ['ident'],
		'properties': {
			'ident': {'type': 'string'},
		}
	})
	async def lost_password(self, request, *, json_data):
		await asyncio.sleep(5)  # Safety time cooldown
		ident = json_data['ident']
		# Locate credentials
		credentials_id = await self.CredentialsService.locate(ident, stop_at_first=True)
		if credentials_id is not None:
			await self.ChangePasswordService.init_password_change(credentials_id)
		else:
			L.warning("No credentials matching '{}'".format(ident))
		response = {'result': 'OK'}  # Since this is public, don't disclose the true result
		return asab.web.rest.json_response(request, response)
