import logging
import base64

import urllib.parse

import aiohttp.web

#

L = logging.getLogger(__name__)

#


# TODO: This is a naive implementation, rework
class BouncerHandler(object):
	"""
	Redirects user to a specified URL after authorization.
	"""

	def __init__(self, app, bouncer_svc):
		self.BouncerService = bouncer_svc
		self.SessionService = app.get_service('seacatauth.SessionService')
		self.CookieService = app.get_service('seacatauth.CookieService')

		web_app = app.WebContainer.WebApp
		web_app.router.add_get('/bouncer', self.bouncer)
		web_app.router.add_get('/bouncer/{base64_url}', self.bouncer)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get('/bouncer', self.bouncer)
		web_app_public.router.add_get('/bouncer/{base64_url}', self.bouncer)


	async def bouncer(self, request):
		"""
		Redirects user to a specified URL after authorization.
		Requires _cookie_introspect to be set in nginx configuration.
		:param request:
		:return:
		"""

		url = request.query.get('url')
		if url is None:
			try:
				base64_url = request.match_info["base64_url"]
				url = base64.urlsafe_b64decode(base64_url.encode('ascii')).decode('ascii')
			except Exception as e:
				L.warning("URL could not be decoded, because '{}'.".format(e))
				return aiohttp.web.HTTPBadRequest()

		# Check that the URL is allowed
		if not self.BouncerService.check_url_allowed(url):
			return aiohttp.web.HTTPBadRequest(reason="URL is not allowed for bouncing.")

		# Obtain the session
		session = await self.CookieService.get_root_session_by_sci(request)

		# Do the authorization if the user is not logged in
		if session is None or session.Credentials.Id is None:

			# TODO: Make the following URLs configurable also for other uses
			# Must be base64 in order to not get unquoted during authorizations etc.
			redirect_uri = "{}/batman&state={}/bouncer/{}".format(
				self.BouncerService.UrlPrefix,
				self.BouncerService.UrlPrefix,
				base64.urlsafe_b64encode(url.encode('ascii')).decode('ascii')
			)
			# Do the authorization
			return aiohttp.web.HTTPFound(
				"{}/openidconnect/authorize?response_type=code&scope=openid&client_id=signin&redirect_uri={}".format(
					self.BouncerService.UrlPrefix, redirect_uri
				)
			)

		else:
			return aiohttp.web.HTTPFound(urllib.parse.unquote(url))
