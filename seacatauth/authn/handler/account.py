import logging
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions
import asab.contextvars
import aiohttp.web

from ... import exceptions, AuditLogger
from ...models.const import ResourceId
from ...openidconnect.utils import AUTHORIZE_PARAMETERS
from .. import schema


L = logging.getLogger(__name__)


class AuthenticationAccountHandler(object):
	"""
	Login and authentication

	---
	tags: ["Login and authentication"]
	"""

	def __init__(self, app, authn_svc):
		self.App = app
		self.AuthenticationService = authn_svc
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.CookieService = app.get_service("seacatauth.CookieService")
		self.BatmanService = app.get_service("seacatauth.BatmanService")
		self.CommunicationService = app.get_service("seacatauth.CommunicationService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_put("/account/impersonate", self.impersonate)
		web_app.router.add_post("/account/impersonate", self.impersonate_and_redirect)


	@asab.web.rest.json_schema_handler(schema.IMPERSONATE)
	@asab.web.auth.require(ResourceId.IMPERSONATE)
	@asab.web.tenant.allow_no_tenant
	async def impersonate(self, request, *, json_data):
		"""
		Impersonate another user

		Open an SSO session impersonated as a different user.
		Response contains a Set-Cookie header with the new root session cookie.
		"""
		from_info = [request.remote]
		ff = request.headers.get("X-Forwarded-For")
		if ff is not None:
			from_info.extend(ff.split(", "))

		target_cid = json_data["credentials_id"]
		authz = asab.contextvars.Authz.get()
		if authz.Session.Session.ParentSessionId is None and authz.Session.Session.Type in {"root", "m2m"}:
			impersonator_root_session = authz.Session
		else:
			impersonator_root_session = await self.SessionService.get(authz.Session.Session.ParentSessionId)

		try:
			session = await self._impersonate(impersonator_root_session, from_info, target_cid)
		except aiohttp.web.HTTPForbidden as e:
			return e

		response = asab.web.rest.json_response(request, {"result": "OK"})
		await self.CookieService.set_session_cookie(
			response=response,
			cookie_value=session.Cookie.Id,
		)
		return response


	@asab.web.auth.require(ResourceId.IMPERSONATE)
	@asab.web.tenant.allow_no_tenant
	async def impersonate_and_redirect(self, request):
		"""
		Impersonate another user

		Open an SSO session impersonated as a different user. Response contains a Set-Cookie header with the new
		root session cookie and redirection to the authorize endpoint. This effectively overwrites user's current
		root cookie. Reference to current root session is kept in the impersonated session.
		On logout, the original root cookie is set again.
		---
		requestBody:
			content:
				application/x-www-form-urlencoded:
					schema:
						type: object
						properties:
							credentials_id:
								type: string
								description: Credentials ID of the impersonation target.
							client_id:
								type: string
								description: Client ID
							redirect_uri:
								type: string
								description:
									URI of the client app to redirect to when the impersonation authorization
									is complete.
							response_type:
								type: string
								description: OAuth response type.
							scope:
								type: string
								description: OAuth scope.
						required:
							- credentials_id
							- client_id
							- redirect_uri
						additionalProperties: True
		"""
		oidc_service = self.App.get_service("seacatauth.OpenIdConnectService")
		client_service = self.App.get_service("seacatauth.ClientService")

		from_info = [request.remote]
		ff = request.headers.get("X-Forwarded-For")
		if ff is not None:
			from_info.extend(ff.split(", "))

		request_data = await request.post()
		target_cid = request_data["credentials_id"]
		authz = asab.contextvars.Authz.get()
		if authz.Session.Session.ParentSessionId is None and authz.Session.Session.Type in {"root", "m2m"}:
			impersonator_root_session = authz.Session
		else:
			impersonator_root_session = await self.SessionService.get(authz.Session.Session.ParentSessionId)

		try:
			session = await self._impersonate(impersonator_root_session, from_info, target_cid)
		except aiohttp.web.HTTPForbidden as e:
			return e

		client_dict = await client_service.get_client(request_data["client_id"])
		query = {
			k: v for k, v in request_data.items()
			if k in AUTHORIZE_PARAMETERS}
		authorize_uri = oidc_service.build_authorize_uri(client_dict, **query)

		response = aiohttp.web.HTTPFound(
			authorize_uri,
			headers={
				"Location": authorize_uri,
				"Refresh": "0;url={}".format(authorize_uri),
			},
			content_type="text/html",
			text="""<!doctype html>\n<html lang="en">\n<head></head><body>...</body>\n</html>\n"""
		)
		await self.CookieService.set_session_cookie(
			response=response,
			cookie_value=session.Cookie.Id,
			client_id=session.OAuth2.ClientId,
		)
		return response


	async def _impersonate(self, impersonator_root_session, impersonator_from_info, target_cid):
		"""
		Create a new impersonated session and log the event.
		"""
		# TODO: Restrict impersonation based on agent X target resource intersection
		impersonator_cid = impersonator_root_session.Credentials.Id
		try:
			session = await self.AuthenticationService.create_impersonated_session(
				impersonator_root_session, target_cid)
		except exceptions.CredentialsNotFoundError:
			AuditLogger.warning("Impersonation failed: Target credentials ID not found", struct_data={
				"impersonator_cid": impersonator_cid,
				"impersonator_sid": impersonator_root_session.SessionId,
				"target_cid": target_cid,
				"from_ip": impersonator_from_info,
			})
			raise aiohttp.web.HTTPForbidden()
		except exceptions.AccessDeniedError:
			AuditLogger.warning("Impersonation failed: Access denied", struct_data={
				"impersonator_cid": impersonator_cid,
				"impersonator_sid": impersonator_root_session.SessionId,
				"target_cid": target_cid,
				"from_ip": impersonator_from_info,
			})
			raise aiohttp.web.HTTPForbidden()
		except Exception as e:
			AuditLogger.exception("Impersonation failed: Unexpected error ({})".format(e), struct_data={
				"impersonator_cid": impersonator_cid,
				"impersonator_sid": impersonator_root_session.SessionId,
				"target_cid": target_cid,
				"from_ip": impersonator_from_info,
			})
			raise aiohttp.web.HTTPForbidden()
		else:
			AuditLogger.log(asab.LOG_NOTICE, "Impersonation successful", struct_data={
				"impersonator_cid": impersonator_cid,
				"impersonator_sid": impersonator_root_session.SessionId,
				"target_cid": target_cid,
				"target_sid": str(session.Session.Id),
				"from_ip": impersonator_from_info,
			})
		return session
