import typing
import logging
import aiohttp
import aiohttp.web
import saml2
import saml2.config
import saml2.client
import saml2.response

from ...exceptions import ExternalLoginError
from .abc import ExternalAuthProviderABC


L = logging.getLogger(__name__)


_MS_ENTRA_AMR = {
	"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password": "password",
	"http://schemas.microsoft.com/claims/multipleauthn": "mfa",
}
_SAML_AMR = {
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos": "kerberos",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Password": "password",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:PGP": "pgp",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword": "srp",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig": "xmldsig",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI": "spki",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard": "smartcard",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI": "smartcard",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient": "tlsclient",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Unspecified": "unspecified",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:X509": "x509",
	"urn:federation:authentication:windows": "windows",
}


class SamlAuthProvider(ExternalAuthProviderABC):
	"""
	Generic SAML 2 login provider

	Example config:
	```conf
	[seacatauth:saml:auth_provider_name]
	idp_metadata_url=https://idp.example.com/federationmetadata.xml
	entity_id=https://my-seacat-auth.example.com/saml/metadata
	key_file=/conf/secret/saml-private-key.pem
	cert_file=/conf/secret/saml-certificate.pem
	label=Login with {auth_provider_name} SAML
	```
	"""

	def __init__(self, external_authentication_svc, config_section_name, config=None):
		super().__init__(external_authentication_svc, config_section_name, config)
		self.SamlClient = self._init_saml_client()


	def _init_saml_client(self):
		for key in ("entity_id", "idp_metadata_url"):
			if key not in self.Config:
				raise ValueError("Missing '{}' in SAML provider configuration.".format(key))

		config_dict = {
			"entityid": self.Config["entity_id"],  # Must be registered at IdP
			"service": {
				"sp": {
					"endpoints": {
						"assertion_consumer_service": [
							(self.CallbackUrl, saml2.BINDING_HTTP_POST),  # Must be registered at IdP
						],
					},
					"allow_unsolicited": False,
					"authn_requests_signed": False,
					"want_response_signed": (
						self.Config.getboolean("want_response_signed") if "want_response_signed" in self.Config
						else False
					),
					"want_assertions_signed": (
						self.Config.getboolean("want_assertions_signed") if "want_assertions_signed" in self.Config
						else True
					),
				}
			},
			"metadata": {
				"remote": [{
					"url": self.Config["idp_metadata_url"]
				}]
			},
		}

		if "key_file" in self.Config and "cert_file" in self.Config:
			config_dict["key_file"] = self.Config["key_file"]
			config_dict["cert_file"] = self.Config["cert_file"]
			config_dict["service"]["sp"]["authn_requests_signed"] = True

		config = saml2.config.Config()
		config.load(config_dict)
		return saml2.client.Saml2Client(config)


	async def prepare_auth_request(self, state: dict, **kwargs) -> typing.Tuple[dict, aiohttp.web.Response]:
		saml_request_id, authn_request = self.SamlClient.prepare_for_authenticate(
			binding=saml2.BINDING_HTTP_REDIRECT,
			relay_state=state["state_id"],
		)

		headers = dict(authn_request.get("headers", []))
		auth_uri = headers.get("Location")
		if not auth_uri:
			raise ExternalLoginError("Missing redirect Location from SAML client.")

		state["request_id"] = saml_request_id
		return state, aiohttp.web.HTTPFound(auth_uri)


	async def process_auth_callback(self, request: aiohttp.web.Request, payload: dict, state: dict, **kwargs) -> dict:
		saml_response = payload.get("SAMLResponse")
		if saml_response is None:
			L.error("No SAMLResponse in request payload", struct_data={
				"provider": self.Type,
			})
			raise ExternalLoginError("Malformed SAML response.")

		try:
			authn_response = self.SamlClient.parse_authn_request_response(
				saml_response,
				binding=saml2.BINDING_HTTP_POST,
				outstanding={state["request_id"]: True},
			)
		except Exception as e:
			L.error("Cannot parse SAML authentication response: {}".format(e), struct_data={
				"provider": self.Type,
			})
			raise ExternalLoginError("Malformed SAML response.") from e

		if not authn_response.status_ok():
			L.error("SAML authentication failed.", struct_data={
				"provider": self.Type,
			})
			raise ExternalLoginError("SAML authentication failed.")

		user_identity = authn_response.get_identity()
		try:
			user_identity["sub"] = authn_response.get_subject().text
		except ValueError as e:
			L.error("Cannot infer subject ID from SAML authentication response.", struct_data={
				"provider": self.Type,
			})
			raise ExternalLoginError("Failed to obtain user metadata from SAML response.") from e

		return user_identity


def _get_attribute(authn_response: saml2.response.AuthnResponse, attribute_name: str) -> typing.List[str]:
	"""
	Get attribute values from SAML response.
	"""
	vals = []
	for stmt in (authn_response.assertion.attribute_statement or []):
		for attr in (stmt.attribute or []):
			if attr.name == attribute_name:
				vals.extend([v.text for v in (attr.attribute_value or []) if hasattr(v, "text")])
	return vals


def _get_amr_values(authn_response: saml2.response.AuthnResponse) -> typing.Set[str]:
	"""
	Get AMR (Authentication Methods References) values from SAML response.
	"""
	values = set()
	for v in _get_attribute(authn_response, "http://schemas.microsoft.com/claims/authnmethodsreferences"):
		if v in _MS_ENTRA_AMR:
			values.add(_MS_ENTRA_AMR[v])

	for v, *_ in authn_response.authn_info():
		if v in _SAML_AMR:
			values.add(_SAML_AMR[v])

	return values
