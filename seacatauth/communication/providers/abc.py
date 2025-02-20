import abc
import logging
import jinja2
import asab


L = logging.getLogger(__name__)


class CommunicationProviderABC(asab.Configurable, abc.ABC):

	Channel = None
	TemplateFilenameFormat = "{locale}-{template_name}.{extension}"
	TemplateExtension = "txt"

	def __init__(self, config_section_name, config=None):
		super().__init__(config_section_name=config_section_name, config=config)
		self.TemplatePath = self.Config.get("template_path")
		if self.TemplatePath is None:
			base_template_path = asab.Config.get("seacatauth:communication", "template_path")
			self.TemplatePath = "{base_template_path}/{channel}".format(
				base_template_path=base_template_path,
				channel=self.Channel
			)
		self.TemplateExtension = self.Config.get("template_extension")
		self.JinjaEnv = jinja2.Environment(
			loader=jinja2.FileSystemLoader(self.TemplatePath)
		)


	async def send_message(self, credentials: dict, message: dict, **kwargs):
		raise NotImplementedError()


	async def build_message(self, credentials: dict, template_id: str, locale: str, **kwargs) -> dict:
		raise NotImplementedError()


	async def build_and_send_message(self, credentials: dict, template_id, locale, **kwargs):
		message = await self.build(template_id, locale, **kwargs)
		await self.send(credentials, message, **kwargs)


	def _get_template(self, locale, template_name):
		template_file_name = self.TemplateFilenameFormat.format(
			template_name=template_name,
			locale=locale,
			extension=self.TemplateExtension
		)
		template = self.JinjaEnv.get_template(template_file_name)
		return template
