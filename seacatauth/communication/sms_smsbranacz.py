import datetime
import logging
import secrets
import aiohttp
import asab
import hashlib

from . import CommunicationProviderABC

#

L = logging.getLogger(__name__)

#


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

	ConfigDefaults = {
		"login": "",
		"password": "",
		"url": "https://api.smsbrana.cz/smsconnect/http.php",
		# smsbrana provides a backup server: https://api-backup.smsbrana.cz/smsconnect/http.php
		"timestamp_format": "%Y%m%dT%H%M%S",  # Use STARTTLS protocol
	}

	def __init__(self, provider_id, config_section_name):
		super().__init__(provider_id, config_section_name)
		self.Login = self.Config.get("login")
		self.Password = self.Config.get("password")
		self.TimestampFormat = self.Config.get("timestamp_format")
		self.URL = self.Config.get("url")

		if "mock" in self.Config:
			raise ValueError("To activate mock mode, use 'url=<mocked>' instead of the 'mock' option.")
		self.MockMode = (self.URL == "<mocked>")
		if self.MockMode:
			L.warning(
				"SMSbrana.cz provider is running in mock mode. "
				"Messages will not be sent, but instead will be printed to log.")

	def _init_template_provider(self):
		pass

	async def send_message(self, *, phone, message_body):
		if phone is None or phone == "":
			L.error("Empty or no phone number specified.")
			raise RuntimeError("Empty or no phone number specified.")

		if isinstance(message_body, str):
			message_list = [message_body]
		else:
			message_list = message_body

		# TODO: proper multi-sms handling
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
