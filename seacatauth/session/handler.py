import logging

import asab
import asab.web.rest
import bson

from seacatauth.decorators import access_control
from .adapter import SessionAdapter

#

L = logging.getLogger(__name__)

#


class SessionHandler(object):

	def __init__(self, app, session_svc):
		self.SessionService = session_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get(r'/session', self.session_list)
		web_app.router.add_get(r'/session/{session_id}', self.session_detail)
		web_app.router.add_delete(r'/session/{session_id}', self.session_delete)
		web_app.router.add_delete(r'/sessions', self.delete_all)
		web_app.router.add_get(r'/sessions/{credentials_id}', self.search_by_credentials_id)
		web_app.router.add_delete(r'/sessions/{credentials_id}', self.delete_by_credentials_id)

		web_app.router.add_delete(r'/public/sessions', self.delete_own_sessions)

		# Public aliases
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_delete(r'/public/sessions', self.delete_own_sessions)


	@access_control("authz:superuser")
	async def session_list(self, request):
		page = int(request.query.get('p', 1)) - 1
		limit = int(request.query.get('i', 10))
		data = await self.SessionService.recursive_list(page, limit)
		return asab.web.rest.json_response(request, data)


	@access_control("authz:superuser")
	async def session_detail(self, request):
		session_id = request.match_info['session_id']
		session = (await self.SessionService.get(session_id)).rest_get()
		children = await self.SessionService.list(query_filter={
			SessionAdapter.FN.Session.ParentSessionId: bson.ObjectId(session_id)
		})
		if children["count"] > 0:
			session["children"] = children
		return asab.web.rest.json_response(request, session)


	@access_control("authz:superuser")
	async def session_delete(self, request):
		session_id = request.match_info['session_id']
		await self.SessionService.delete(session_id)
		response = {
			"result": "OK",
		}
		return asab.web.rest.json_response(request, response)


	@access_control("authz:superuser")
	async def delete_all(self, request, *, credentials_id):
		L.warning("Deleting all sessions", struct_data={
			"requested_by": credentials_id
		})
		await self.SessionService.delete_all_sessions()
		return asab.web.rest.json_response(request, {"result": "OK"})


	@access_control("authz:superuser")
	async def search_by_credentials_id(self, request):
		"""
		List sessions of a given credentials
		"""
		credentials_id = request.match_info.get("credentials_id")
		page = int(request.query.get('p', 1)) - 1
		limit = int(request.query.get('i', 10))
		sessions = await self.SessionService.list(page, limit, query_filter={
			SessionAdapter.FN.Credentials.Id: credentials_id
		})
		return asab.web.rest.json_response(request, sessions)


	@access_control("authz:superuser")
	async def delete_by_credentials_id(self, request, *, credentials_id):
		"""
		Delete all sessions of a given credentials
		"""
		requester_cid = credentials_id

		credentials_id = request.match_info.get("credentials_id")
		L.warning("Deleting all user sessions", struct_data={
			"cid": credentials_id,
			"requested_by": requester_cid
		})
		await self.SessionService.delete_sessions_by_credentials_id(credentials_id)
		return asab.web.rest.json_response(request, {"result": "OK"})


	@access_control()
	async def delete_own_sessions(self, request, *, credentials_id):
		"""
		Delete all sessions of the current user
		"""
		L.warning("Deleting all user sessions", struct_data={
			"cid": credentials_id
		})
		await self.SessionService.delete_sessions_by_credentials_id(credentials_id)
		return asab.web.rest.json_response(request, {"result": "OK"})
