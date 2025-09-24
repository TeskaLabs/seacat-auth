import logging
import aiohttp
import asab
import asab.web.rest.json

from .abc import CommunicationProviderABC


L = logging.getLogger(__name__)


TEMPLATE_FILES = {
	"invitation": "Tenant Invitation.md",
	"password_reset": "Password Reset.md",
	"welcome_password_reset": "Welcome and Password Reset.md",
}


class AsabIrisEmailProvider(CommunicationProviderABC):

	Channel = "email"
	TemplateExtension = None
	ConfigDefaults = {
		"url": "http://localhost:8896",
		"template_path": "/Templates/Email/",
	}

	def __init__(self, app, config_section_name, config=None):
		super().__init__(app, config_section_name, config=config)
		self.AsabIrisUrl = self.Config.get("url").rstrip("/") + "/"
		self.TemplateBasePath = self.Config.get("template_path")


	async def can_send_to_target(self, credentials: dict) -> bool:
		if not await self.is_enabled():
			return False
		try:
			_get_email_address(credentials)
			return True
		except KeyError:
			return False


	async def is_enabled(self) -> bool:
		url = "{}{}".format(self.AsabIrisUrl, "features")
		try:
			async with _asab_iris_session(self.App) as session:
				async with session.get(url) as resp:
					response = await resp.json()
					if resp.status != 200:
						L.error("Error response from ASAB Iris.", struct_data=response)
						return False
		except aiohttp.ClientError as e:
			L.error("Error connecting to ASAB Iris: {}".format(e))
			return False

		enabled_orchestrators = response.get("orchestrators", [])
		return "email" in enabled_orchestrators


	async def build_message(self, credentials: dict, template_id: str, locale: str, **kwargs) -> dict:
		raise NotImplementedError()


	async def send_message(self, credentials: dict, message: dict, **kwargs):
		raise NotImplementedError()


	async def build_and_send_message(self, credentials: dict, template_id: str, locale: str, **kwargs):
		email_decl = {
			"to": [_get_email_address(credentials)],
			"body": {
				"template": self._get_template_path(template_id),
				"params": kwargs,
			}
		}
		data = asab.web.rest.json.JSONDumper(pretty=False)(email_decl)

		url = "{}{}".format(self.AsabIrisUrl, "send_email")
		try:
			async with _asab_iris_session(self.App) as session:
				async with session.put(url, data=data, headers={"Content-Type": "application/json"}) as resp:
					response = await resp.json()
					if resp.status == 200:
						L.log(asab.LOG_NOTICE, "Email sent.")
					else:
						L.error("Error response from ASAB Iris.", struct_data=response)
						raise RuntimeError("Email delivery failed.")
		except aiohttp.ClientError as e:
			L.error("Error connecting to ASAB Iris: {}".format(e))
			raise RuntimeError("Email delivery failed.")


	def _get_template_path(self, template_id: str) -> str:
		return "{}{}".format(self.TemplateBasePath, TEMPLATE_FILES[template_id])


def _get_email_address(credentials: dict) -> str:
	email = credentials.get("email")
	if not email:
		raise KeyError("Credentials do not contain 'email'.")
	return email


def _asab_iris_session(app, *args, **kwargs):
	discovery_service = app.get_service("asab.DiscoveryService")
	if discovery_service is not None:
		return discovery_service.session(*args, **kwargs)
	else:
		return aiohttp.ClientSession(*args, **kwargs)
