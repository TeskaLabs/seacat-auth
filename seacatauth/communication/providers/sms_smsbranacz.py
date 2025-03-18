import datetime
import logging
import secrets
import aiohttp
import asab
import hashlib
import re

from .abc import CommunicationProviderABC


L = logging.getLogger(__name__)


class SMSBranaCZProvider(CommunicationProviderABC):
	"""
	SMSBrana API documentation https://www.smsbrana.cz/dokumenty/SMSconnect_dokumentace.pdf

	Example smsbrana.cz API response:
	```xml
	<?xml version='1.0' encoding='utf-8'?>
	<result>
	<err>10</err>
	</result>
	```
	# TODO: add dict of error codes, try to parse response with xml.etree.ElementTree
	#   tree = xml.etree.ElementTree.ElementTree(xml.etree.ElementTree.fromstring(xmlstring))
	"""

	Channel = "sms"
	TemplateExtension = "txt"
	ConfigDefaults = {
		"login": "",
		"password": "",
		"url": "https://api.smsbrana.cz/smsconnect/http.php",
		# smsbrana provides a backup server: https://api-backup.smsbrana.cz/smsconnect/http.php
	}

	def __init__(self, app, config_section_name, config=None):
		super().__init__(app, config_section_name, config=config)
		self.Login = self.Config.get("login")
		self.Password = self.Config.get("password")
		self.TimestampFormat = "%Y%m%dT%H%M%S"
		self.URL = self.Config.get("url")

		if "mock" in self.Config:
			raise ValueError("To activate mock mode, use 'url=<mocked>' instead of the 'mock' option.")
		self.MockMode = (self.URL == "<mocked>")
		if self.MockMode:
			L.warning(
				"SMSbrana.cz provider is running in mock mode. "
				"Messages will not be sent, but instead will be printed to log.")


	async def can_send_to_target(self, credentials: dict) -> bool:
		if not await self.is_enabled():
			return False
		try:
			_get_phone_number(credentials)
			return True
		except KeyError:
			return False


	async def is_enabled(self) -> bool:
		return True


	async def build_message(self, credentials: dict, template_id: str, locale: str, **kwargs) -> dict:
		template = self._get_template(locale, template_id)
		message_body = _split_long_message(template.render(kwargs))
		message = {
			"message_body": message_body,
			"phone": _get_phone_number(credentials)
		}
		return message


	async def send_message(self, credentials: dict, message: dict, **kwargs):
		phone = _get_phone_number(credentials)

		message_list = message["message_body"]
		for text in message_list:
			url_params = {
				"action": "send_sms",
				"login": self.Login,
				"time": None,
				"salt": None,
				"auth": None,
				"number": phone,
				"message": text
			}

			time = datetime.datetime.now(datetime.timezone.utc).strftime(self.TimestampFormat)
			salt = secrets.token_urlsafe(16)
			url_params["time"] = time
			url_params["salt"] = salt
			url_params["auth"] = hashlib.md5((self.Password + time + salt).encode("utf-8")).hexdigest()

			if self.MockMode:
				L.log(
					asab.LOG_NOTICE, "SMSBrana.cz provider is in mock mode. Message will not be sent.",
					struct_data=url_params
				)
				return

			async with aiohttp.ClientSession() as session:
				async with session.get(self.URL, params=url_params) as resp:
					if resp.status != 200:
						L.error("SMSBrana.cz responsed with {}".format(resp), await resp.text())
						raise RuntimeError("SMS delivery failed.")
					response_body = await resp.text()

			if "<err>0</err>" not in response_body:
				L.error("SMS delivery failed. SMSBrana.cz response: {}".format(response_body))
				raise RuntimeError("SMS delivery failed.")
			else:
				L.log(asab.LOG_NOTICE, "SMS sent")


SPLITTER = re.compile(r"\n(?:\s*\n)+")


def _split_long_message(message_body: str) -> list:
	"""
	Split long SMS into several messages.
	"""
	messages = SPLITTER.split(message_body)
	return messages


def _get_phone_number(credentials: dict) -> str:
	phone = credentials.get("phone")
	if not phone:
		raise KeyError("Credentials do not contain 'phone'.")
	return phone
