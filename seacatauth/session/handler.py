import logging
import bson
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant

from ..models import Session
from ..models.const import ResourceId


L = logging.getLogger(__name__)


class SessionHandler(object):
	"""
	Sessions

	---
	tags: ["Sessions"]
	"""

	def __init__(self, app, session_svc):
		self.SessionService = session_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/session", self.session_list)
		web_app.router.add_get("/session/{session_id}", self.session_detail)
		web_app.router.add_delete("/session/{session_id}", self.session_delete)
		web_app.router.add_delete("/sessions", self.delete_all)
		web_app.router.add_get("/sessions/{credentials_id}", self.search_by_credentials_id)
		web_app.router.add_delete("/sessions/{credentials_id}", self.delete_by_credentials_id)

		web_app.router.add_delete("/account/sessions", self.delete_own_sessions)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.SESSION_ACCESS)
	async def session_list(self, request):
		"""
		List sessions

		---
		parameters:
		-	name: p
			in: query
			description: Page number
			schema:
				type: integer
		-	name: i
			in: query
			description: Items per page
			schema:
				type: integer
		-	name: include_expired
			in: query
			description: Whether to include expired sessions in the results
			required: false
			schema:
				type: boolean
				default: no
		"""
		page = int(request.query.get("p", 1)) - 1
		limit = int(request.query.get("i", 10))
		include_expired = asab.config.utils.string_to_boolean(request.query.get("include_expired", "no"))
		data = await self.SessionService.recursive_list(page, limit, include_expired=include_expired)
		return asab.web.rest.json_response(request, data)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.SESSION_ACCESS)
	async def session_detail(self, request):
		"""
		Get session detail
		"""
		session_id = request.match_info["session_id"]
		session = (await self.SessionService.get(session_id)).rest_get()
		children = await self.SessionService.list(query_filter={
			Session.FN.Session.ParentSessionId: bson.ObjectId(session_id)
		})
		if children["count"] > 0:
			session["children"] = children
		return asab.web.rest.json_response(request, session)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.SESSION_TERMINATE)
	async def session_delete(self, request):
		"""
		Terminate a session
		"""
		session_id = request.match_info["session_id"]
		await self.SessionService.delete(session_id)
		response = {
			"result": "OK",
		}
		return asab.web.rest.json_response(request, response)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require_superuser
	async def delete_all(self, request):
		"""
		Terminate all sessions
		"""
		authz = asab.contextvars.Authz.get()
		L.warning("Deleting all sessions", struct_data={
			"requested_by": authz.CredentialsId
		})
		await self.SessionService.delete_all_sessions()
		return asab.web.rest.json_response(request, {"result": "OK"})


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.SESSION_ACCESS)
	async def search_by_credentials_id(self, request):
		"""
		List all active sessions of given credentials

		---
		parameters:
		-	name: p
			in: query
			description: Page number
			schema:
				type: integer
		-	name: i
			in: query
			description: Items per page
			schema:
				type: integer
		"""
		credentials_id = request.match_info.get("credentials_id")
		page = int(request.query.get("p", 1)) - 1
		limit = int(request.query.get("i", 10))
		sessions = await self.SessionService.list(page, limit, query_filter={
			Session.FN.Credentials.Id: credentials_id
		})
		return asab.web.rest.json_response(request, sessions)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.SESSION_TERMINATE)
	async def delete_by_credentials_id(self, request):
		"""
		Terminate all sessions of given credentials
		"""
		authz = asab.contextvars.Authz.get()
		credentials_id = request.match_info.get("credentials_id")
		L.warning("Deleting all user sessions", struct_data={
			"cid": credentials_id,
			"requested_by": authz.CredentialsId,
		})
		await self.SessionService.delete_sessions_by_credentials_id(credentials_id)
		return asab.web.rest.json_response(request, {"result": "OK"})


	@asab.web.tenant.allow_no_tenant
	async def delete_own_sessions(self, request):
		"""
		Terminate all the current user's sessions
		"""
		authz = asab.contextvars.Authz.get()
		L.warning("Deleting all user sessions", struct_data={
			"cid": authz.CredentialsId,
		})
		await self.SessionService.delete_sessions_by_credentials_id(authz.CredentialsId)
		return asab.web.rest.json_response(request, {"result": "OK"})
