import logging
import typing

import asab
import urllib.parse

from .abc import CommunicationProviderABC
from .builders import MessageBuilderABC
from .. import exceptions

#

L = logging.getLogger(__name__)

#


class CommunicationService(asab.Service):
	"""
	Creates messages from templates and sends them via their respective channels.

	Example config:
	```ini
	[seacatauth:communication]
	default_locale=en
	template_path=/etc/message_templates

	[seacatauth:communication:email:smtp]
	username=test
	password=testpass
	sender_email_address=test@test.info

	[seacatauth:communication:sms:smsbranacz]
	username=test
	password=testpass
	```

	Example usage:
	```python
	comm_service = app.get_service("seacatauth.CommunicationService")
	await comm_service.password_reset(
		email="sojka@test.com",
		locale="cs",
		username="sojka",
		reset_url=reset_url,
		welcome=True
	)
	```
	"""

	CHANNELS = frozenset(["email", "sms"])

	def __init__(self, app, service_name="seacatauth.CommunicationService"):
		super().__init__(app, service_name)
		self.DefaultLocale = asab.Config.get("seacatauth:communication", "default_locale")
		self.AppName = asab.Config.get("seacatauth:communication", "app_name", fallback=None)
		if self.AppName is None:
			auth_webui_base_url = app.AuthWebUiUrl
			parsed = urllib.parse.urlparse(auth_webui_base_url)
			self.AppName = parsed.netloc
		self.CommunicationProviders: typing.Dict[str, CommunicationProviderABC] = {}
		self.MessageBuilders: typing.Dict[str, MessageBuilderABC] = {}
		relevant_sections = [s for s in asab.Config.sections() if s.startswith("seacatauth:communication:")]
		for section in relevant_sections:
			_, _, channel, provider_name = section.rsplit(":", 3)

			provider_id = "seacatauth.communication.{}.{}".format(channel, provider_name)

			# Assuming there can be only one provider per channel (only one email provider, one sms provider)
			if channel not in self.CHANNELS:
				L.error("Unsupported channel: '{}'".format(channel))
				continue
			if channel in self.CommunicationProviders:
				L.error("There is already a '{}' provider".format(channel))
				continue
			if provider_id == "seacatauth.communication.email.smtp":
				from . import SMTPProvider
				from .builders import EmailMessageBuilder
				self.CommunicationProviders[channel] = SMTPProvider(provider_id, section)
				self.MessageBuilders[channel] = EmailMessageBuilder(section)
			elif provider_id == "seacatauth.communication.sms.smsbranacz":
				from . import SMSBranaCZProvider
				from .builders import SMSMessageBuilder
				self.CommunicationProviders[channel] = SMSBranaCZProvider(provider_id, section)
				self.MessageBuilders[channel] = SMSMessageBuilder(section)
			else:
				L.error("Unsupported communication provider: '{}'".format(provider_id))


	def is_enabled(self, channel=None):
		if not channel:
			return len(self.CommunicationProviders) > 0
		else:
			return channel in self.CommunicationProviders

	def get_communication_provider(self, channel):
		provider = self.CommunicationProviders.get(channel)
		if provider is None:
			raise KeyError("No communication provider for '{}' channel configured.".format(channel))
		return provider


	def get_message_builder(self, channel):
		builder = self.MessageBuilders.get(channel)
		if builder is None:
			raise KeyError("No message builder for '{}' channel configured.".format(channel))
		return builder


	async def password_reset(self, *, credentials, reset_url, welcome=False):
		if not self.is_enabled():
			raise exceptions.CommunicationNotConfiguredError()
		channels = ["email", "sms"]
		template_id = "password_reset_welcome" if welcome else "password_reset"
		success = []
		for channel in ["email", "sms"]:
			try:
				await self.build_and_send_message(
					template_id=template_id,
					channel=channel,
					email=credentials.get("email"),
					phone=credentials.get("phone"),
					username=credentials.get("username"),
					reset_url=reset_url,
				)
				success.append(channel)
				continue
			except exceptions.MessageDeliveryError:
				L.error("Failed to send message via specified channel.", struct_data={
					"channel": channel, "template": template_id, "cid": credentials["_id"]})
				continue

		if len(success) == 0:
			raise exceptions.MessageDeliveryError(
				"Failed to deliver message on all channels.", template_id=template_id, channel=channels)


	async def invitation(self, *, credentials, tenants, registration_uri, expires_at=None):
		if not self.is_enabled():
			raise exceptions.CommunicationNotConfiguredError()
		await self.build_and_send_message(
			template_id="invitation",
			channel="email",
			email=credentials.get("email"),
			username=credentials.get("username"),
			tenants=tenants,
			registration_uri=registration_uri,
			expires_at=expires_at,
		)


	async def sms_login(self, *, credentials: dict, otp: str):
		if not self.is_enabled():
			raise exceptions.CommunicationNotConfiguredError()
		await self.build_and_send_message(
			template_id="login_otp",
			channel="sms",
			phone=credentials.get("phone"),
			otp=otp
		)


	async def build_and_send_message(self, template_id, channel, **kwargs):
		if not self.is_enabled():
			raise exceptions.CommunicationNotConfiguredError()
		try:
			provider = self.get_communication_provider(channel)
			message_builder = self.get_message_builder(channel)
		except KeyError:
			raise exceptions.MessageDeliveryError("Communication channel not configured.", channel=channel)

		try:
			message_dict = message_builder.build_message(
				template_name=template_id,
				locale=self.DefaultLocale,
				app_name=self.AppName,
				**kwargs
			)
		except Exception as e:
			raise exceptions.MessageDeliveryError(
				"Failed to build message from template.", template_id=template_id, channel=channel) from e

		try:
			await provider.send_message(**message_dict)
		except Exception as e:
			L.error("Failed to deliver message (): {}".format(e.__class__.__name__,e))
			raise exceptions.MessageDeliveryError(
				"Failed to deliver message.", template_id=template_id, channel=channel) from e
