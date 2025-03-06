import logging
import typing
import asab
import urllib.parse

from .providers.abc import CommunicationProviderABC
from .. import exceptions


L = logging.getLogger(__name__)


class CommunicationService(asab.Service):
	"""
	Creates messages from templates and sends them via their respective channels.

	Example config:
	```ini
	[seacatauth:communication]
	default_locale=en
	template_path=/etc/message_templates

	[seacatauth:communication:email:iris]
	url=http://

	[seacatauth:communication:sms:smsbranacz]
	username=test
	password=testpass
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
		relevant_sections = [s for s in asab.Config.sections() if s.startswith("seacatauth:communication:")]
		for config_section_name in relevant_sections:
			_, _, channel, provider_name = config_section_name.rsplit(":", 3)

			if channel not in self.CHANNELS:
				# There can be only one provider per channel
				raise ValueError("Unsupported channel: '{}'.".format(channel))
			if channel in self.CommunicationProviders:
				raise ValueError("Another '{}' provider is already registered.".format(channel))

			if channel == "email" and provider_name == "iris":
				from .providers import AsabIrisEmailProvider
				self.CommunicationProviders[channel] = AsabIrisEmailProvider(self.App, config_section_name)
			elif channel == "email" and provider_name == "smtp":
				from .providers import SMTPEmailProvider
				self.CommunicationProviders[channel] = SMTPEmailProvider(self.App, config_section_name)
			elif channel == "sms" and provider_name == "smsbranacz":
				from .providers import SMSBranaCZProvider
				self.CommunicationProviders[channel] = SMSBranaCZProvider(self.App, config_section_name)
			else:
				L.error("Unsupported communication provider: '{}'".format(config_section_name))


	def is_enabled(self):
		return len(self.CommunicationProviders) > 0


	def is_channel_enabled(self, channel):
		return channel in self.CommunicationProviders


	def get_communication_provider(self, channel):
		provider = self.CommunicationProviders.get(channel)
		if provider is None:
			raise KeyError("No communication provider for '{}' channel configured.".format(channel))
		return provider


	async def password_reset(self, *, credentials, reset_url, new_user=False):
		template_id = "new_user_password" if new_user else "password_reset"
		success = []
		channels = ["email", "sms"]
		for channel in channels:
			try:
				await self.build_and_send_message(
					credentials=credentials,
					template_id=template_id,
					channel=channel,
					username=credentials.get("username"),
					password_reset_url=reset_url,
				)
			except exceptions.CommunicationChannelNotAvailableError:
				L.debug("Channel is not available", struct_data={
					"channel": channel, "template": template_id, "cid": credentials["_id"]
				})
				continue
			except exceptions.MessageDeliveryError:
				L.error("Failed to send message via specified channel.", struct_data={
					"channel": channel, "template": template_id, "cid": credentials["_id"]
				})
				continue

			success.append(channel)

		if len(success) == 0:
			raise exceptions.MessageDeliveryError(
				"Failed to deliver message on all channels.", template_id=template_id, channel=channels)


	async def invitation(self, *, credentials, tenants, registration_uri, expires_at=None):
		await self.build_and_send_message(
			credentials=credentials,
			template_id="invitation",
			channel="email",
			username=credentials.get("username"),
			tenant=", ".join(tenants),
			registration_url=registration_uri,
			expires_at=expires_at,
		)


	async def sms_login(self, *, credentials: dict, otp: str):
		await self.build_and_send_message(
			credentials=credentials,
			template_id="login_otp",
			channel="sms",
			otp=otp,
		)


	async def build_and_send_message(
		self,
		credentials: dict,
		template_id: str,
		channel: str,
		*,
		locale: str = None,
		**kwargs
	):
		if not self.is_enabled():
			raise exceptions.CommunicationNotConfiguredError()

		try:
			provider = self.get_communication_provider(channel)
		except KeyError:
			raise exceptions.CommunicationChannelNotAvailableError("Channel not configured.", channel=channel)

		if not provider.can_send_to_target(credentials):
			raise exceptions.CommunicationChannelNotAvailableError(
				"Channel not available for credentials.", channel=channel, cid=credentials["_id"])

		locale = locale or self.DefaultLocale

		try:
			await provider.build_and_send_message(credentials, template_id, locale, **kwargs)
		except Exception as e:
			L.error("Failed to deliver message ({}): {}".format(e.__class__.__name__, e))
			raise exceptions.MessageDeliveryError(
				"Failed to deliver message.", template_id=template_id, channel=channel) from e
