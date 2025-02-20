import logging
import email.mime.multipart
import email.mime.text
import aiosmtplib
import re
import asab

from .abc import CommunicationProviderABC


L = logging.getLogger(__name__)


class AsabIrisEmailProvider(CommunicationProviderABC):

	Channel = "email"
	TemplateExtension = None

	ConfigDefaults = {
		"url": "http://localhost:8896",
	}

	def __init__(self, app, config_section_name, config=None):
		super().__init__(config_section_name, config=config)
		self.AsabIrisUrl = self.Config.get("url")
		self.TemplateBasePath = "/Templates/Email/"


	async def build_message(self, credentials: dict, template_id: str, locale: str, **kwargs) -> dict:
		raise NotImplementedError()


	async def send_message(self, credentials: dict, message: dict, **kwargs):
		raise NotImplementedError()


	async def build_and_send_message(self, credentials: dict, template_id: str, locale: str, **kwargs):
		email_decl = {
			"to": [credentials["email"]],
			"body": {
				"template": self._get_template_path(template_id),
				"params": kwargs,
			}
		}

		url = "{}/send_mail".format(self.AsabIrisUrl)
		discovery_service = self.get_service("asab.DiscoveryService")
		# TODO: Regular session if DiscoveryService is None
		async with discovery_service.session() as session:
			async with session.put(url, json=email_decl) as resp:
				response = await resp.json()  # comes from asab-iris in the unified format (internationalization)
				if resp.status == 200:
					L.log(asab.LOG_NOTICE, "Email sent.", struct_data={"result": response})
				else:
					raise RuntimeError("Email delivery failed: Error response from ASAB Iris.")


	def _get_template_path(self, template_id: str) -> str:
		templates = {
			"invitation": "Export.md",
			"new_user_password": "Export.md",
			"password_reset": "Export.md",
		}
		return "{}{}".format(self.TemplateBasePath, templates[template_id])
