import abc
import logging
import jinja2
import asab


L = logging.getLogger(__name__)


class CommunicationProviderABC(asab.Configurable, abc.ABC):

	Channel = None
	TemplateFilenameFormat = "{locale}-{template_name}.{extension}"
	TemplateExtension = "txt"

	def __init__(self, app, config_section_name, config=None):
		super().__init__(config_section_name=config_section_name, config=config)
		self.App = app
		self.TemplatePath = self.Config.get("template_path")
		if self.TemplatePath is None:
			base_template_path = asab.Config.get("seacatauth:communication", "template_path")
			self.TemplatePath = "{base_template_path}/{channel}".format(
				base_template_path=base_template_path,
				channel=self.Channel
			)
		self.JinjaEnv = jinja2.Environment(
			loader=jinja2.FileSystemLoader(self.TemplatePath)
		)


	async def can_send_to_target(self, credentials: dict) -> bool:
		return await self.is_enabled()


	async def is_enabled(self) -> bool:
		raise NotImplementedError()


	async def send_message(self, credentials: dict, message: dict, **kwargs):
		raise NotImplementedError()


	async def build_message(self, credentials: dict, template_id: str, locale: str, **kwargs) -> dict:
		raise NotImplementedError()


	async def build_and_send_message(self, credentials: dict, template_id: str, locale: str, **kwargs):
		message = await self.build_message(credentials, template_id, locale, **kwargs)
		await self.send_message(credentials, message, **kwargs)


	def _get_template(self, locale, template_name):
		template_file_name = self.TemplateFilenameFormat.format(
			template_name=template_name,
			locale=locale,
			extension=self.TemplateExtension
		)
		template = self.JinjaEnv.get_template(template_file_name)
		return template
