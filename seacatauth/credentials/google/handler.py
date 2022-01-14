import pprint
import urllib
import urllib.parse
import logging

import aiohttp.web

#

L = logging.getLogger(__name__)

#


class GoogleOAuth2Handler(object):

	# TODO: This is just a proof-of-concept

	def __init__(self, app):

		web_app = app.WebContainer.WebApp
		web_app.router.add_get('/openidconnect/google_oauth2', self.authorize)
		web_app.router.add_get('/openidconnect/google_oauth2_redirect', self.redirect)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get('/openidconnect/google_oauth2', self.authorize)
		web_app_public.router.add_get('/openidconnect/google_oauth2_redirect', self.redirect)


	async def authorize(self, request):
		return aiohttp.web.HTTPFound(
			"https://accounts.google.com/o/oauth2/auth?" + urllib.parse.urlencode({
				'response_type': 'code',
				'redirect_uri': 'http://localhost:8080/openidconnect/google_oauth2_redirect',
				'scope': 'email profile openid',
				'client_id': '',
			})
		)


	async def redirect(self, request):
		data = {
			'code': request.query['code'],
			'client_id': '',
			'client_secret': '',
			'grant_type': 'authorization_code',
			'redirect_uri': 'http://localhost:8080/openidconnect/google_oauth2_redirect'
		}

		async with aiohttp.ClientSession() as session:
			async with session.post('https://oauth2.googleapis.com/token', data=data) as resp:
				if resp.status != 200:
					raise RuntimeError("Failed to retriev a token from google: {}".format(resp.status))
				token_resp = await resp.json()

			async with session.get('https://oauth2.googleapis.com/tokeninfo?id_token=' + token_resp['id_token']) as resp:
				if resp.status != 200:
					raise RuntimeError("Failed to retriev a ID token from google: {}".format(resp.status))
				id_token = await resp.json()


		pprint.pprint(token_resp)

		pprint.pprint(id_token)

		return aiohttp.web.Response(text="Yeah!", content_type="text/plain")
