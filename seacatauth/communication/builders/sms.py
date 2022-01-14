import re

from .abc import MessageBuilderABC


SPLITTER = re.compile(r"\n(?:\s*\n)+")


class SMSMessageBuilder(MessageBuilderABC):

	Channel = "sms"
	ConfigDefaults = {
		"template_extension": "txt"
		# "template_path": "/etc/message-templates/sms/",  # Inherited from [seacatauth:communication]
	}

	def __init__(self, config_section_name, config=None):
		super().__init__(config_section_name, config)

	def build_message(self, template_name, locale, *, phone=None, **kwargs):
		message = super(SMSMessageBuilder, self).build_message(template_name, locale, **kwargs)
		message["message_body"] = self._split_long_message(message["message_body"])
		if phone is None:
			raise TypeError("'phone' not specified")
		message["phone"] = phone
		return message

	def _split_long_message(self, message_body: str) -> list:
		"""
		Split long SMS into several messages.
		"""
		messages = SPLITTER.split(message_body)
		return messages
