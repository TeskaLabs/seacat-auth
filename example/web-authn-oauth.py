import logging

import aiohttp
import aiohttp.web

import asab
import asab.web
import asab.web.rest
import asab.web.authn
import asab.web.authn.oauth

#

L = logging.getLogger(__name__)

#

asab.Config.add_defaults({
	'example:oauth': {
		'listen': '0.0.0.0 8081',
	},

	'oauth2:oidc': {
		"token_url": "http://localhost:8080/openidconnect/token",
		"userinfo_url": "http://localhost:8080/openidconnect/userinfo",
	}
})


class MyOAuthSecuredApplication(asab.Application):
	"""
	MyOAuthSecuredApplication serves endpoints, which can only access clients authorized via OAuth 2.0 server.

	In order to try the example with GitHub, follow this guide to request an access token.
	You will need to create your mock GitHub OAuth application and call authorize and access_token endpoints,
	as the guide suggest:
	https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/#web-application-flow

	Then access the MyOAuthSecuredApplication user endpoint via:

	curl "http://127.0.0.1:8080/user" -H "Authorization: Bearer github.com-<YOUR_ACCESS_TOKEN>"

	The following message should then be displayed:

	<YOUR_GITHUB_EMAIL>, you have accessed our secured "user" endpoint.

	"""

	async def initialize(self):
		# Loading the web service module
		self.add_module(asab.web.Module)

		# Locate web service
		websvc = self.get_service("asab.WebService")

		# Create a dedicated web container
		container = asab.web.WebContainer(websvc, 'example:oauth')

		# Load the OAuth module
		self.add_module(asab.web.authn.oauth.Module)
		oauth_client_service = self.get_service("asab.OAuthClientService")

		# Select OAuth providers
		oauth_client_service.append_method(asab.web.authn.oauth.OpenIDConnectMethod())

		# Add a GitHub
		oauth_client_service.append_method(asab.web.authn.oauth.GitHubOAuthMethod())

		# Add middleware for authentication via oauth2 and register useful OAuth endpoints
		oauth_client_service.configure(container=container)

		# Enable exception to JSON exception middleware
		container.WebApp.middlewares.append(asab.web.rest.JsonExceptionMiddleware)

		# Add a route
		container.WebApp.router.add_get('/', self.index)

	@asab.web.authn.authn_required_handler
	async def index(self, request, *, identity):
		return aiohttp.web.Response(
			text='Hello "{}",\nyou have accessed our secured endpoint.'.format(request.UserInfo['name'])
		)


if __name__ == '__main__':
	app = MyOAuthSecuredApplication()
	app.run()
