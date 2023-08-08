import abc
import logging

import jinja2

import asab

#

L = logging.getLogger(__name__)

#


class MessageBuilderABC(asab.Configurable, abc.ABC):
	"""
	Constructs a message object (dictionary)
	"""

	Channel = None
	TemplateFilenameFormat = "{locale}-{template_name}.{extension}"

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

	def build_message(self, template_name, locale, *args, **kwargs):
		template = self._get_template(locale, template_name)
		L.debug("Rendering {} template {} ({})".format(self.Channel, template_name, locale))
		message_body = template.render(kwargs)
		message = {"message_body": message_body}
		return message

	def _get_template(self, locale, template_name):
		template_file_name = self.TemplateFilenameFormat.format(
			template_name=template_name,
			locale=locale,
			extension=self.TemplateExtension
		)
		template = self.JinjaEnv.get_template(template_file_name)
		return template
