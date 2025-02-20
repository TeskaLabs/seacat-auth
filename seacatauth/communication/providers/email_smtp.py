import logging
import email.mime.multipart
import email.mime.text
import aiosmtplib
import re
import asab

from .abc import CommunicationProviderABC


L = logging.getLogger(__name__)


class SMTPEmailProvider(CommunicationProviderABC):

	Channel = "email"
	TemplateExtension = "html"

	ConfigDefaults = {
		"host": "localhost",
		"port": "",
		"user": "",
		"password": "",
		"ssl": "no",
		"starttls": "yes",
	}

	def __init__(self, config_section_name, config=None):
		super().__init__(config_section_name, config=config)

		if "smtp" in asab.Config:
			self.Config.update(asab.Config["smtp"])
		self.SSL = self.Config.getboolean("ssl")
		self.StartTLS = self.Config.getboolean("starttls")
		self.Host = self.Config.get("host")
		self.User = self.Config.get("user")
		self.Password = self.Config.get("password")
		self.From = self.Config.get("from", None)

		self.MockMode = (self.Host == "<mocked>")
		if self.MockMode:
			L.warning(
				"SMTP provider is running in mock mode. "
				"Emails will not be sent, but instead will be printed to log.")

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


	async def build_message(self, credentials: dict, template_id, locale, **kwargs) -> dict:
		to = _get_email_address(credentials)

		template = self._get_template(locale, template_id)
		message_body = template.render(kwargs)
		message = {
			"message_body": message_body,
			"subject": _get_subject_from_body(message_body),
			"sender": self.From,
			"to": to,
		}
		if to is None:
			raise TypeError("'to' not specified")
		message["to"] = to
		return message


	async def send_message(self, credentials: dict, message: dict, **kwargs):
		to = _get_email_address(credentials)

		# Prepare Message
		subject = _get_subject_from_body(message["message_body"])
		msg = email.mime.multipart.MIMEMultipart()
		msg.preamble = subject
		msg["Subject"] = subject
		msg["From"] = self.From
		msg["To"] = to

		if self.MockMode:
			L.log(
				asab.LOG_NOTICE, "SMTP provider is in mock mode. Email will not be sent.",
				struct_data={**msg, "message_body": message}
			)
		else:
			msg.attach(email.mime.text.MIMEText(message["message_body"], "html", "utf-8"))
			result = await aiosmtplib.send(
				msg,
				sender=self.From,
				recipients=[to],
				hostname=self.Host,
				port=self.Port,
				username=self.User if len(self.User) > 0 else None,
				password=self.Password,
				use_tls=self.SSL,
				start_tls=self.StartTLS
			)
			L.log(asab.LOG_NOTICE, "Email sent.", struct_data={"result": result[1]})

		return


def _get_subject_from_body(message_body):
	pattern = re.compile(r"<meta email-subject=\"(.*?)\"")
	match = pattern.search(message_body)
	if match is not None:
		return match.group(1)
	pattern = re.compile(r"<meta email-subject='(.*?)'")
	match = pattern.search(message_body)
	if match is not None:
		return match.group(1)


def _get_email_address(credentials: dict) -> str:
	email = credentials.get("email")
	if not email:
		raise KeyError("Credentials do not contain 'email'.")
	return email
