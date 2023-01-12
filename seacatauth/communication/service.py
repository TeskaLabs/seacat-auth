import logging
import re
import typing

import asab
import urllib.parse

from .abc import CommunicationProviderABC
from .builders import MessageBuilderABC

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
			auth_webui_base_url = asab.Config.get("general", "auth_webui_base_url")
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
				L.warning("Unsupported channel: '{}'".format(channel))
				continue
			if channel in self.CommunicationProviders:
				L.warning("There is already a '{}' provider".format(channel))
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
				L.warning("Unsupported communication provider: '{}'".format(provider_id))

		if len(self.CommunicationProviders) == 0:
			L.warning("No communication provider configured.")

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

	def parse_channels(self, channels):
		# TODO: proper bool operator handling:
		#   if any channel of the or_group returns True (=successful send), break the loop
		#   Maybe this could be an iterative decorator, e.g.
		#   ```
		#   @communication.channels("email&sms")
		#   async def password_reset(...)
		#   ```
		"""
		Channels will be a string of channel names joined by | and &.
		It is evaluated in a boolean-like manner from left to right.
		E.g. The string "sms&slack|email&push" commands the service to send an SMS AND a Slack message.
		If either fails, it shall both send an email AND a push notification.
		"""
		if re.match(r"^[\w&|]+$", channels) is None:
			raise ValueError("Channel string '{}' contains invalid characters.".format(channels))
		for or_group in channels.split("|"):
			for channel in or_group.split("&"):
				yield channel

	async def password_reset(
		self, *,
		phone=None, email=None, locale=None, username=None, reset_url=None, welcome=False
	):
		channels = "email&sms"
		if welcome is True:
			message_id = "password_reset_welcome"
		else:
			message_id = "password_reset"
		locale = locale or self.DefaultLocale

		success = []
		for channel in self.parse_channels(channels):
			try:
				provider = self.get_communication_provider(channel)
				message_builder = self.get_message_builder(channel)
			except KeyError as e:
				L.warning("Cannot send {} message: {}".format(channel, e))
				continue

			# Template provider produces a message object with "message_body"
			# and other attributes characteristic for the channel
			try:
				message_dict = message_builder.build_message(
					template_name=message_id,
					locale=locale,
					phone=phone,
					email=email,
					username=username,
					reset_url=reset_url,
					app_name=self.AppName
				)
			except Exception as e:
				# TODO: custom errors: MessageBuild(CommunicationError)
				L.error("Message build failed: {} ({})".format(type(e).__name__, str(e)))
				continue

			# Communication provider sends the message
			try:
				status = await provider.send_message(**message_dict)
				success.append(status)
			except Exception as e:
				# TODO: custom errors: MessageDelivery(CommunicationError)
				L.error("Message delivery failed: {} ({})".format(type(e).__name__, str(e)))

		# If no channel succeeds to send the message, raise error
		# TODO: handle this in the channel iterator once it's implemented
		if True not in success:
			L.error("Communication failed on all channels.", struct_data={
				"channels": channels
			})
			return False
		return True


	async def invitation(
		self, *,
		phone=None, email=None, locale=None, username=None, tenants, registration_uri, expires_at=None
	):
		channel = "email"
		message_id = "invitation"
		locale = locale or self.DefaultLocale

		success = False
		try:
			provider = self.get_communication_provider(channel)
			message_builder = self.get_message_builder(channel)
		except KeyError as e:
			L.warning("Cannot send {} message: {}".format(channel, e))
			return False

		# Template provider produces a message object with "message_body"
		# and other attributes characteristic for the channel
		try:
			message_dict = message_builder.build_message(
				template_name=message_id,
				locale=locale,
				phone=phone,
				email=email,
				username=username,
				tenants=tenants,
				registration_uri=registration_uri,
				expires_at=expires_at,
				app_name=self.AppName
			)
		except Exception as e:
			L.error("Message build failed: {} ({})".format(type(e).__name__, str(e)))
			return False

		# Communication provider sends the message
		try:
			success = success or await provider.send_message(**message_dict)
		except Exception as e:
			L.error("Message delivery failed: {} ({})".format(type(e).__name__, str(e)))

		return True


	async def sms_login(
		self, *,
		phone=None, locale=None, otp=None
	):
		channels = "sms"
		message_id = "login_otp"
		locale = locale or self.DefaultLocale

		success = []
		for channel in self.parse_channels(channels):
			try:
				provider = self.get_communication_provider(channel)
				message_builder = self.get_message_builder(channel)
			except KeyError as e:
				L.warning("Cannot send {} message: {}".format(channel, e))
				continue

			try:
				message_dict = message_builder.build_message(
					template_name=message_id,
					locale=locale,
					phone=phone,
					otp=otp,
					app_name=self.AppName
				)
			except Exception as e:
				L.error("Message build failed: {} ({})".format(type(e).__name__, str(e)))
				continue

			try:
				status = await provider.send_message(**message_dict)
				success.append(status)
			except Exception as e:
				L.error("Message delivery failed: {} ({})".format(type(e).__name__, str(e)))

		if True not in success:
			L.error("Communication failed on all channels.", struct_data={
				"channels": channels
			})
			return False
		return True
