import logging
import urllib.parse

import aiohttp.web
import asab
import asab.web.rest

from .service import ExternalLoginService
from ..decorators import access_control
from ..cookie.utils import set_cookie, delete_cookie

#

L = logging.getLogger(__name__)

#


class ExternalLoginHandler(object):
	"""
	External login

	---
	tags: ["External login"]
	"""

	def __init__(self, app, external_login_svc: ExternalLoginService):
		self.App = app
		self.ExternalLoginService = external_login_svc
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get(self.ExternalLoginService.ExternalLoginPath, self.login)
		web_app.router.add_get(self.ExternalLoginService.AddExternalLoginPath, self.register_external_login)
		web_app.router.add_delete(self.ExternalLoginService.ExternalLoginPath, self.unregister_external_login)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get(self.ExternalLoginService.ExternalLoginPath, self.login)
		web_app_public.router.add_get(self.ExternalLoginService.AddExternalLoginPath, self.register_external_login)
		web_app_public.router.add_delete(self.ExternalLoginService.ExternalLoginPath, self.unregister_external_login)


	async def login(self, request):
		"""
		Log in with a registered external provider account
		"""
		cookie_svc = self.App.get_service("seacatauth.CookieService")
		client_svc = self.App.get_service("seacatauth.ClientService")

		# TODO: Implement state parameter for XSRF prevention
		# state = request.query.get("state")
		# if state is None:
		# 	L.error("State parameter not provided in external login response")
		state = None

		login_provider_type = request.match_info["ext_login_provider"]
		provider = self.ExternalLoginService.get_provider(login_provider_type)
		user_info = await provider.do_external_login(request)

		if user_info is None:
			L.error("Cannot obtain user info from external login provider")
			response = self._login_redirect_response(state=state, error="external_login_failed")
			delete_cookie(self.App, response)
			return response

		sub = user_info.get("sub")
		if sub is None:
			L.error("Cannot obtain sub id from external login provider")
			response = self._login_redirect_response(state=state, error="external_login_failed")
			delete_cookie(self.App, response)
			return response

		sub = str(sub)

		# Get credentials by sub
		try:
			el_credentials = await self.ExternalLoginService.get(login_provider_type, sub)
			credentials_id = el_credentials["cid"]
		except KeyError:
			response = self._login_redirect_response(state=state, error="external_login_failed")
			delete_cookie(self.App, response)
			return response

		# Create a placeholder login session
		# TODO: Save the external login provider as a login factor
		login_descriptors = []
		login_session = await self.AuthenticationService.create_login_session(
			credentials_id=credentials_id,
			client_public_key=None,
			login_descriptors=login_descriptors,
			ident=None
		)

		# Create ad-hoc login descriptor
		login_factor = "!ext-{}".format(login_provider_type)
		login_session.AuthenticatedVia = {
			"id": "!external",
			"label": "Login via {}".format(login_provider_type),
			"factors": [
				{"id": login_factor, "type": login_factor}
			]
		}

		# Get the IP addresses where the login request came from
		access_ips = [request.remote]
		ff = request.headers.get("X-Forwarded-For")
		if ff is not None:
			access_ips.extend(ff.split(", "))

		# Finish login and create session
		session = await self.AuthenticationService.login(login_session, from_info=access_ips)
		if session is None:
			L.error("Failed to create session")
			response = self._login_redirect_response(state=state, error="external_login_failed")
			delete_cookie(self.App, response)
			return response

		L.log(asab.LOG_NOTICE, "External login successful", struct_data={
			"cid": credentials_id,
			"login_type": provider.Type
		})
		response = self._my_account_redirect_response(state=state)

		# Get cookie domain
		cookie_domain = cookie_svc.RootCookieDomain
		if hasattr(login_session, "ClientId"):
			try:
				client = await client_svc.get(login_session.ClientId)
				cookie_domain = client.get("cookie_domain")
			except KeyError:
				L.error("Client not found.", struct_data={"client_id": login_session.ClientId})

		set_cookie(self.App, response, session, cookie_domain)

		return response


	@access_control()
	async def register_external_login(self, request, *, credentials_id):
		"""
		Register a new external login provider account
		"""
		# TODO: Implement state parameter for XSRF prevention
		# state = request.query.get("state")
		# if state is None:
		# 	L.error("State parameter not provided in external login response")
		state = None

		login_provider_type = request.match_info["ext_login_provider"]

		# Check if the credentials don't have this login type enabled already
		login_exists = False

		try:
			await self.ExternalLoginService.get_sub(credentials_id, login_provider_type)
			login_exists = True
		except KeyError:
			pass

		if login_exists:
			L.error("External login of this type already exists for credentials", struct_data={
				"cid": credentials_id,
				"type": login_provider_type
			})
			response = self._my_account_redirect_response(state=state, error="external_login_already_activated")
			return response

		login_provider = self.ExternalLoginService.get_provider(login_provider_type)
		user_info = await login_provider.add_external_login(request)
		if user_info is None:
			L.error("Cannot obtain user info from external login provider")
			return self._my_account_redirect_response(state=state, error="external_login_failed")

		sub = user_info.get("sub")
		if sub is None:
			L.error("Cannot obtain 'sub' field from external login provider", struct_data={
				"cid": credentials_id,
				"type": login_provider_type
			})
			return self._my_account_redirect_response(state=state, error="external_login_failed")

		sub = str(sub)

		# Check if the sub is not already registered with different credentials
		already_used = False
		try:
			await self.ExternalLoginService.get(login_provider_type, sub)
			already_used = True
		except KeyError:
			pass

		if already_used:
			L.error("External login already used by different credentials", struct_data={
				"request_cid": credentials_id,
				"type": login_provider_type,
				"sub": sub,
			})
			response = self._my_account_redirect_response(state=state, error="external_login_not_activated")
			return response

		# Update credentials
		try:
			await self.ExternalLoginService.create(
				credentials_id, login_provider_type, sub, user_info.get("email"), user_info.get("ident"))
		except Exception as e:
			L.error("{} when creating external login credentials: {}".format(type(e).__name__, str(e)), struct_data={
				"cid": credentials_id,
				"type": login_provider_type,
				"sub": sub,
			})
			response = self._my_account_redirect_response(state=state, error="external_login_not_activated")
			return response

		L.log(asab.LOG_NOTICE, "External login successfully added", struct_data={
			"cid": credentials_id,
			"login_type": login_provider_type
		})

		# Redirect to home screen
		return self._my_account_redirect_response(state=state, result="external_login_activated")


	@access_control()
	async def unregister_external_login(self, request, *, credentials_id):
		"""
		Unregister an external login provider account
		"""
		provider_type = request.match_info["ext_login_provider"]

		try:
			el_credentials = await self.ExternalLoginService.get_sub(credentials_id, provider_type)
		except KeyError as e:
			raise aiohttp.web.HTTPNotFound(text=str(e))
		await self.ExternalLoginService.delete(provider_type, sub=el_credentials["s"])

		L.log(asab.LOG_NOTICE, "External login successfully removed", struct_data={
			"cid": credentials_id,
			"type": provider_type,
		})

		response = {"result": "OK"}
		return asab.web.rest.json_response(request, response)


	def _login_redirect_response(self, state=None, error=None):
		# TODO: Revise with custom per-client login URIs
		if state is not None:
			query = "?state={}".format(state)
		else:
			query = ""

		if error is not None:
			fragment_query = "?error={}".format(error)
		else:
			fragment_query = ""

		redirect_uri = "{}{}#{}{}".format(
			self.ExternalLoginService.AuthUiBaseUrl,
			query,
			self.ExternalLoginService.LoginUiFragmentPath,
			fragment_query,
		)

		response = aiohttp.web.HTTPFound(
			redirect_uri,
			headers={
				# TODO: Specify location
				"Refresh": "0;url={}".format(redirect_uri),
			},
			content_type="text/html",
			text="""<!doctype html>\n<html lang="en">\n<head></head><body>...</body>\n</html>\n"""
		)
		return response


	def _my_account_redirect_response(self, state=None, error=None, result=None):
		# TODO: Revise with custom per-client login URIs
		if state is not None:
			query = "?state={}".format(state)
		else:
			query = ""

		fragment_query_params = []
		if error is not None:
			fragment_query_params.append(("error", error))
		if result is not None:
			fragment_query_params.append(("result", result))
		if len(fragment_query_params) > 0:
			hash_query = "?{}".format(urllib.parse.urlencode(fragment_query_params))
		else:
			hash_query = ""

		redirect_uri = "{}{}#{}{}".format(
			self.ExternalLoginService.AuthUiBaseUrl,
			query,
			self.ExternalLoginService.HomeUiFragmentPath,
			hash_query,
		)

		response = aiohttp.web.HTTPFound(
			redirect_uri,
			headers={
				# TODO: Specify location
				"Refresh": "0;url={}".format(redirect_uri),
			},
			content_type="text/html",
			text="""<!doctype html>\n<html lang="en">\n<head></head><body>...</body>\n</html>\n"""
		)
		return response
