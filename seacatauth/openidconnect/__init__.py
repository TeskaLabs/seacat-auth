import asab

from .service import OpenIdConnectService

from .handler.authorize import AuthorizeHandler
from .handler.token import TokenHandler
from .handler.userinfo import UserInfoHandler
from .handler.introspect import TokenIntrospectionHandler
from .handler.session import SessionHandler
from .handler.public_keys import PublicKeysHandler
from .handler.discovery import DiscoveryHandler


class OpenIdConnectModule(asab.Module):
	'''
	https://openid.net/specs/openid-connect-core-1_0.html
	'''

	def __init__(self, app):
		super().__init__(app)

		public_api_base_url = app.PublicOpenIdConnectApiUrl
		auth_webui_base_url = app.AuthWebUiUrl

		self.OpenIdConnectService = OpenIdConnectService(app)
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.RoleService = app.get_service("seacatauth.RoleService")

		self.AuthorizeHandler = AuthorizeHandler(
			app,
			self.OpenIdConnectService,
			self.CredentialsService,
			public_api_base_url=public_api_base_url,
			auth_webui_base_url=auth_webui_base_url
		)

		self.TokenHandler = TokenHandler(app, self.OpenIdConnectService)
		self.UserInfoHandler = UserInfoHandler(app, self.OpenIdConnectService)
		self.TokenIntrospectionHandler = TokenIntrospectionHandler(
			app,
			self.OpenIdConnectService,
			self.CredentialsService
		)
		self.SessionHandler = SessionHandler(app, self.OpenIdConnectService, self.SessionService)
		self.PublicKeysHandler = PublicKeysHandler(app, self.OpenIdConnectService)
		self.DiscoveryHandler = DiscoveryHandler(app, self.OpenIdConnectService)
