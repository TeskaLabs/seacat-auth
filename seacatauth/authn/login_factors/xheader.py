import logging

from .abc import LoginFactorABC

#

L = logging.getLogger(__name__)

#


class XHeaderFactor(LoginFactorABC):
	"""
	Authenticate based on the value of a specified HTTP header.

	It is necessary that the specified header is present in all login requests; missing header will cause the login
	to intentionally fail in order to prevent header injection.

	=====
	NGINX Example: Authenticate requests coming to a specific port
	=====

	Configure Nginx to add port number to header.
	```nginx
	server {
		# Listen at two ports
		listen 443 default_server ssl http2;
		listen 444 ssl http2;
		...
		location /api/seacat_auth/public {
			rewrite               ^/api/seacat_auth/(.*) /$1 break;
			proxy_set_header      Host $host;
			# Add port number to X-Server-Port header
			proxy_set_header      X-Server-Port $server_port;
			proxy_pass            ...;
		}
		...
	}
	```

	Configure SeacatAuth `login-descriptors.json`
	```json
	[
		{
			"id": "default",
			"label": "Use recommended login.",
			"factors": [
				[
					{"id": "internal-network", "type": "xheader", "header": "X-Server-Port", "value": "444"},
					{"id": "password", "type": "password"}
				],
				[
					{"id": "smscode", "type": "smscode"},
					{"id": "password", "type": "password"}
				]
			]
		}
	]
	```

	With this setting, users that arrive to port 444 will be asked only for password, while those
	arriving to 443 will need to authorize with password AND smscode.

	"""
	Type = "xheader"

	def __init__(self, authn_service, config):
		super().__init__(authn_service, config)
		self.Header = config["header"]
		self.Value = str(config["value"])

	def serialize(self):
		return {
			**super().serialize(),
			"header": self.Header,
			"value": self.Value,
		}

	async def is_eligible(self, login_data) -> bool:
		"""
		:returns True if the HTTP header value matches the configured value.
		:returns False if the HTTP header value doesn't match the configured value.
		:raises ValueError if the HTTP header is missing.
		"""
		headers = login_data.get("request_headers")
		if headers is None:
			return False
		return self._check_header(headers)

	async def authenticate(self, login_session, request_data) -> bool:
		"""
		:returns True if the HTTP header value matches the configured value.
		:returns False if the HTTP header value doesn't match the configured value.
		:raises ValueError if the HTTP header is missing.
		"""
		return self._check_header(request_data["request_headers"])

	def _check_header(self, request_headers) -> bool:
		request_header = request_headers.get(self.Header)
		if request_header is None:
			# !! Faulty configuration !!
			# The check must raise an error to prevent HTTP header injection attacks
			raise ValueError("Header '{}' not present in request".format(self.Header))
		if self.Value == request_header:
			return True
		return False
