import logging
import re

import aiohttp
import aiohttp.web

from ..generic import nginx_introspection
from .utils import set_cookie, delete_cookie

from ..openidconnect.session import oauth2_session_builder

from ..session import (
	credentials_session_builder,
	authz_session_builder,
	cookie_session_builder,
	login_descriptor_session_builder,
)

#

L = logging.getLogger(__name__)

#


class CookieHandler(object):


	def __init__(self, app, cookie_svc, session_svc, credentials_svc):
		self.App = app
		self.CookieService = cookie_svc
		self.SessionService = session_svc
		self.CredentialsService = credentials_svc
		self.RBACService = app.get_service("seacatauth.RBACService")

		self.CookiePattern = re.compile(
			"(^{cookie}=[^;]*; ?|; ?{cookie}=[^;]*|^{cookie}=[^;]*)".format(cookie=self.CookieService.CookieName)
		)

		web_app = app.WebContainer.WebApp
		web_app.router.add_post('/cookie/nginx', self.nginx)
		web_app.router.add_get('/cookie/entry/{domain_id}', self.cookie_request)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post('/cookie/nginx', self.nginx)
		web_app_public.router.add_get('/cookie/entry/{domain_id}', self.cookie_request)


	async def authenticate_request(self, request):
		return await self.CookieService.get_session_by_sci(request)


	async def nginx(self, request):
		"""
		Validate the session cookie and exchange it for a Bearer token.
		Optionally check for resource access.
		Add requested user info to headers.

		Example Nginx setup:
		```nginx
		# Protected location
		location /my-app {
			auth_request /_cookie_introspect;
			auth_request_set      $authorization $upstream_http_authorization;
			proxy_set_header      Authorization $authorization;
			proxy_pass            http://my-app:8080
		}

		# Introspection endpoint
		location = /_cookie_introspect {
			internal;
			proxy_method          POST;
			proxy_set_body        "$http_authorization";
			proxy_pass            http://seacat-auth-svc:8081/cookie/nginx?add=credentials&resource=my-app:access;
		}
		```
		"""

		response = await nginx_introspection(
			request,
			self.authenticate_request,
			self.CredentialsService,
			self.SessionService,
			self.RBACService,
			self.App.get_service("seacatauth.OpenIdConnectService"),
		)
		if response.status_code != 200:
			delete_cookie(self.App, response)
			return response

		# Delete SeaCat cookie from Cookie header unless "keepcookie" param is passed in query
		# TODO: Move this to generic.nginx_introspection
		#    (issue: dependency on self.CookiePattern)
		keep_cookie = request.query.get("keepcookie", None)
		cookie_string = request.headers.get(aiohttp.hdrs.COOKIE)

		if keep_cookie is None:
			cookie_string = self.CookiePattern.sub("", cookie_string)

		response.headers[aiohttp.hdrs.COOKIE] = cookie_string

		return response


	async def cookie_request(self, request):
		"""
		Exchange authorization code for cookie and redirect afterwards.
		"""
		grant_type = request.query.get("grant_type")
		if grant_type != "authorization_code":
			L.error("Grant type not supported", struct_data={"grant_type": grant_type})
			return aiohttp.web.HTTPBadRequest()

		# Use the code to get session ID
		code = request.query.get("code")
		root_session = await self.CookieService.get_session_by_authorization_code(code)
		if root_session is None:
			return aiohttp.web.HTTPBadRequest()

		# TODO: Where to get the tenants from?
		tenants = None
		scope = frozenset(["userinfo:*"])

		# TODO: Choose builders based on scope
		session_builders = [
			await credentials_session_builder(self.CredentialsService, root_session.Credentials.Id, scope),
			await authz_session_builder(
				tenant_service=self.CookieService.TenantService,
				role_service=self.CookieService.RoleService,
				credentials_id=root_session.Credentials.Id,
				tenants=tenants,
			),
			login_descriptor_session_builder(root_session.LoginDescriptor),
			cookie_session_builder(),
		]

		# TODO: Temporary solution. Root session should have no OAuth2 data.
		#   Remove once ID token support is fully implemented.
		oauth2_data = {
			"scope": None,
			"client_id": None,
		}
		session_builders.append(oauth2_session_builder(oauth2_data))

		requested_expiration = request.query.get("expiration")
		if requested_expiration is not None:
			requested_expiration = int(requested_expiration)

		session = await self.SessionService.create_session(
			session_type="cookie",
			parent_session=root_session,
			expiration=requested_expiration,
			session_builders=session_builders,
		)

		# Construct the response
		# TODO: Dynamic redirect (instead of static URL from config)
		domain_id = request.match_info["domain_id"]
		if domain_id not in self.CookieService.ApplicationCookies:
			L.error("Invalid domain ID", struct_data={"domain_id": domain_id})

		redirect_uri = self.CookieService.ApplicationCookies[domain_id]["redirect_uri"]

		response = aiohttp.web.HTTPFound(
			redirect_uri,
			headers={
				"Refresh": '0;url=' + redirect_uri,
				"Location": redirect_uri,
			},
			content_type="text/html",
			text="<!doctype html>\n<html lang=\"en\">\n<head></head><body>...</body>\n</html>\n"
		)

		# TODO: Verify that the request came from the correct domain
		try:
			set_cookie(self.App, response, session, domain_id)
		except KeyError:
			L.error("Failed to set cookie", struct_data={"sid": session.Session.Id, "domain_id": domain_id})
			return

		return response
