import jinja2
import re
import asab

from .abc import MessageBuilderABC


class EmailMessageBuilder(MessageBuilderABC):

	Channel = "email"
	ConfigDefaults = {
		"template_extension": "html",
		"from": "auth@seacatauth.info",
		# "template_path": "/etc/message-templates/email/",  # Inherited from [seacatauth:communication]
	}

	def __init__(self, config_section_name, config=None):
		super().__init__(config_section_name, config)
		self.JinjaEnv.autoescape = jinja2.select_autoescape(['html', 'xml'])

		if "smtp" in asab.Config:
			self.Config.update(asab.Config["smtp"])
		if "sender_email_address" in self.Config:
			asab.LogObsolete.warning(
				"Config option 'sender_email_address' in '[smtp]' has been renamed to 'from'. "
				"Please update your configuration file.",
				struct_data={"eol": "2024-01-31"})
			self.From = self.Config.get("sender_email_address", None)
		else:
			self.From = self.Config.get("from", None)

	def build_message(self, template_name, locale, *, email=None, **kwargs):
		message = super(EmailMessageBuilder, self).build_message(template_name, locale, **kwargs)
		message["subject"] = self._get_subject_from_body(message["message_body"])
		message["sender"] = self.From
		if email is None:
			raise TypeError("'email' not specified")
		message["to"] = email
		return message

	def _get_subject_from_body(self, message_body):
		pattern = re.compile(r"<meta email-subject=\"(.*?)\"")
		match = pattern.search(message_body)
		if match is not None:
			return match.group(1)
		pattern = re.compile(r"<meta email-subject='(.*?)'")
		match = pattern.search(message_body)
		if match is not None:
			return match.group(1)
