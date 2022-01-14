import logging
import email.mime.multipart
import email.mime.text
import aiosmtplib

import asab

from . import CommunicationProviderABC

#

L = logging.getLogger(__name__)

#


class SMTPProvider(CommunicationProviderABC):

	Channel = "email"

	ConfigDefaults = {
		"host": "localhost",
		"port": "",
		"user": "",
		"password": "",
		"ssl": "no",  # Use TLS/SSL for connection
		"starttls": "yes",  # Use STARTTLS protocol
	}

	def __init__(self, provider_id, config_section_name):
		super().__init__(provider_id, config_section_name)

		self.SSL = self.Config.getboolean("ssl")
		self.StartTLS = self.Config.getboolean("starttls")
		self.Host = self.Config.get("host")
		self.User = self.Config.get("user")
		self.Password = self.Config.get("password")

		port = self.Config.get("port")
		if len(port) == 0:
			if self.SSL:
				self.Port = 465
			elif self.StartTLS:
				self.Port = 587
			else:
				self.Port = 25
		else:
			self.Port = int(port)

	async def send_message(self, *, sender, to, subject, message_body, text_type="html", cc=None, bcc=None):
		"""
		Send an outgoing email with the given parameters.

		:param sender: From whom the email is being sent
		:type sender: str

		:param to: A list of recipient email addresses.
		:type to: list

		:param subject: The subject of the email.
		:type subject: str

		:param text: The text of the email.
		:type text: str

		:param text_type: Mime subtype of text, defaults to 'plain' (can be 'html').
		:type text: str

		Optional Parameters:
		:param cc: A list of Cc email addresses.
		:param bcc: A list of Bcc email addresses.
		"""

		if not isinstance(to, list):
			to = [to]

		# Prepare Message
		msg = email.mime.multipart.MIMEMultipart()
		msg.preamble = subject
		msg['Subject'] = subject
		msg['From'] = sender
		msg['To'] = ', '.join(to)
		if cc is not None:
			msg['Cc'] = ', '.join(cc)
		if bcc is not None:
			msg['Bcc'] = ', '.join(bcc)

		msg.attach(email.mime.text.MIMEText(message_body, text_type, 'utf-8'))

		result = await aiosmtplib.send(
			msg,
			sender=sender,
			recipients=to,
			hostname=self.Host,
			port=self.Port,
			username=self.User if len(self.User) > 0 else None,
			password=self.Password,
			use_tls=self.SSL,
			start_tls=self.StartTLS
		)

		L.log(asab.LOG_NOTICE, "Email sent", struct_data={'result': result[1]})
		return True
