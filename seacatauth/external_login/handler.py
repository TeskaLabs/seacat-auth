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

	def __init__(self, app, external_login_svc: ExternalLoginService):
		self.App = app
		self.ExternalLoginService = external_login_svc
		self.CookieService = app.get_service("seacatauth.CookieService")
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get(self.ExternalLoginService.ExternalLoginPath, self.login)
		web_app.router.add_get(self.ExternalLoginService.AddExternalLoginPath, self.add_external_login)
		web_app.router.add_delete(self.ExternalLoginService.ExternalLoginPath, self.delete_external_login)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get(self.ExternalLoginService.ExternalLoginPath, self.login)
		web_app_public.router.add_get(self.ExternalLoginService.AddExternalLoginPath, self.add_external_login)
		web_app_public.router.add_delete(self.ExternalLoginService.ExternalLoginPath, self.delete_external_login)


	async def login(self, request):
		state = request.query.get("state")
		if state is None:
			L.warning("State parameter not provided in external login response")

		code = request.query.get("code")
		if code is None:
			L.error("Authentication code not provided in external login response")
			response = self._login_redirect_response(state=state, result="EXTERNAL-LOGIN-FAILED")
			delete_cookie(self.App, response)
			return response

		login_provider_type = request.match_info["ext_login_provider"]
		provider = self.ExternalLoginService.get_provider(login_provider_type)
		user_info = await provider.do_external_login(code)

		if user_info is None:
			L.error("Cannot obtain user info from external login provider")
			return self._my_account_redirect_response(state=state, result="EXTERNAL-LOGIN-FAILED")

		sub = user_info.get("sub")
		if sub is None:
			L.error("Cannot obtain sub id from external login provider")
			response = self._login_redirect_response(state=state, result="EXTERNAL-LOGIN-FAILED")
			delete_cookie(self.App, response)
			return response

		sub = str(sub)

		# Get credentials by sub
		try:
			el_credentials = await self.ExternalLoginService.get(login_provider_type, sub)
			credentials_id = el_credentials["cid"]
		except KeyError:
			credentials_id = None
		if credentials_id is None:
			try:
				credentials = await self.CredentialsService.get_by_external_login_sub(login_provider_type, sub)
				# TODO: Migrate external login data to the dedicated collection?
				credentials_id = credentials["_id"]
			except KeyError:
				credentials_id = None

		if credentials_id is None:
			response = self._login_redirect_response(state=state, result="EXTERNAL-LOGIN-FAILED-UNKNOWN-USER")
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
			response = self._login_redirect_response(state=state, result="EXTERNAL-LOGIN-FAILED")
			delete_cookie(self.App, response)
			return response

		L.log(asab.LOG_NOTICE, "External login successful", struct_data={
			"cid": credentials_id,
			"login_type": provider.Type
		})
		response = self._my_account_redirect_response(state=state, result="EXTERNAL-LOGIN-SUCCESSFUL")
		set_cookie(self.App, response, session)

		return response


	@access_control()
	async def add_external_login(self, request, *, credentials_id):
		state = request.query.get("state")
		# if state is None:
		# 	L.warning("State parameter not provided in external login response")

		code = request.query.get("code")
		if code is None:
			L.error("Authentication code not provided in query")
			raise aiohttp.web.HTTPBadRequest()

		login_provider_type = request.match_info["ext_login_provider"]

		# Check if the credentials don't have this login type enabled already
		login_exists = False
		cred_obj = await self.CredentialsService.get(credentials_id)
		if "external_login" in cred_obj \
			and cred_obj["external_login"].get(login_provider_type, "") != "":
			login_exists = True

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
			response = self._my_account_redirect_response(state=state, result="EXTERNAL-LOGIN-FAILED-ALREADY-SET")
			return response

		login_provider = self.ExternalLoginService.get_provider(login_provider_type)
		user_info = await login_provider.add_external_login(code)
		if user_info is None:
			L.error("Cannot obtain user info from external login provider")
			return self._my_account_redirect_response(state=state, result="EXTERNAL-LOGIN-FAILED")

		sub = user_info.get("sub")
		if sub is None:
			L.error("Cannot obtain 'sub' field from external login provider", struct_data={
				"type": login_provider_type
			})
			return self._my_account_redirect_response(state=state, result="EXTERNAL-LOGIN-FAILED")

		sub = str(sub)

		# Check if the sub is not already registered with different credentials
		already_used = False
		try:
			await self.CredentialsService.get_by_external_login_sub(login_provider_type, sub)
			already_used = True
		except KeyError:
			pass
		try:
			await self.CredentialsService.get_by_external_login_sub(login_provider_type, sub)
			already_used = True
		except KeyError:
			pass

		if already_used:
			L.error("External login already used by different credentials", struct_data={
				"type": login_provider_type,
				"sub": sub,
			})
			response = self._my_account_redirect_response(state=state, result="EXTERNAL-LOGIN-FAILED-ALREADY-IN-USE")
			return response

		# Update credentials
		try:
			await self.ExternalLoginService.create(credentials_id, login_provider_type, sub)
		except Exception as e:
			L.error("{} when creating external login credentials: {}".format(type(e).__name__, str(e)), struct_data={
				"cid": credentials_id,
				"type": login_provider_type,
				"sub": sub,
			})
			response = self._my_account_redirect_response(state=state, result="EXTERNAL-LOGIN-FAILED")
			return response

		L.log(asab.LOG_NOTICE, "External login successfully added", struct_data={
			"cid": credentials_id,
			"login_type": login_provider_type
		})

		# Redirect to home screen
		return self._my_account_redirect_response(state=state, result="EXTERNAL-LOGIN-ADDED")


	@access_control()
	async def delete_external_login(self, request, *, credentials_id):
		provider_type = request.match_info["ext_login_provider"]

		cred_obj = await self.CredentialsService.get(credentials_id)
		if "external_login" in cred_obj and cred_obj["external_login"].get(provider_type, "") != "":
			cred_provider = self.CredentialsService.get_provider(credentials_id)
			field_name = "external_login.{}".format(provider_type)
			await cred_provider.update(credentials_id, update={field_name: ""})
		else:
			el_credentials = await self.ExternalLoginService.get_sub(credentials_id, provider_type)
			await self.ExternalLoginService.delete(provider_type, sub=el_credentials["s"])

		cred_provider = self.CredentialsService.get_provider(credentials_id)
		field_name = "external_login.{}".format(provider_type)

		await cred_provider.update(credentials_id, update={field_name: ""})

		L.log(asab.LOG_NOTICE, "External login successfully removed", struct_data={
			"cid": credentials_id,
			"type": provider_type,
		})

		response = {"result": "OK"}
		return asab.web.rest.json_response(request, response)


	def _login_redirect_response(self, state=None, result=None):
		query_params = []
		if state is not None:
			query_params.append(("state", state))
		if result is not None:
			query_params.append(("result", result))
		if len(query_params) > 0:
			redirect_uri = "{}?{}".format(
				self.ExternalLoginService.LoginScreenUrl,
				urllib.parse.urlencode(query_params)
			)
		else:
			redirect_uri = self.ExternalLoginService.LoginScreenUrl

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


	def _my_account_redirect_response(self, state=None, result=None):
		query_params = []
		if state is not None:
			query_params.append(("state", state))
		if result is not None:
			query_params.append(("result", result))
		if len(query_params) > 0:
			redirect_uri = "{}?{}".format(
				self.ExternalLoginService.HomeScreenUrl,
				urllib.parse.urlencode(query_params)
			)
		else:
			redirect_uri = self.ExternalLoginService.HomeScreenUrl

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
