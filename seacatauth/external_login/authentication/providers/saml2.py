import typing
import logging
import aiohttp
import aiohttp.web
import saml2
import saml2.config
import saml2.client
import saml2.response

from seacatauth.external_login.exceptions import ExternalLoginError
from .abc import ExternalAuthProviderABC


L = logging.getLogger(__name__)


class Saml2AuthProvider(ExternalAuthProviderABC):
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
		config_dict = {
			"entityid": self.Config["entity_id"],  # Must be registered at IdP
			"service": {
				"sp": {
					"endpoints": {
						"assertion_consumer_service": [
							(self.CallbackUrl, saml2.BINDING_HTTP_POST),  # Must be registered at IdP
						],
					},
					"allow_unsolicited": True,
					"authn_requests_signed": False,
					"want_response_signed": False,
					"want_assertions_signed": True,
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
		_, authn_request = self.SamlClient.prepare_for_authenticate(
			binding=saml2.BINDING_HTTP_REDIRECT,
			relay_state=state["state_id"],
		)
		assert authn_request["method"] == "GET"
		auth_uri = dict(authn_request["headers"])["Location"]
		return state, aiohttp.web.HTTPFound(auth_uri)


	async def process_auth_callback(self, request: aiohttp.web.Request, payload: dict, state: dict, **kwargs) -> dict:
		saml_response = payload.get("SAMLResponse")
		if saml_response is None:
			L.error("No SAMLResponse in request payload", struct_data={
				"provider": self.Type,
				"payload": payload,
			})
			raise ExternalLoginError("Malformed SAML response.")

		try:
			authn_response = self.SamlClient.parse_authn_request_response(
				saml_response,
				binding=saml2.BINDING_HTTP_POST
			)
		except Exception as e:
			L.error("Cannot parse SAML authentication response: {}".format(e), struct_data={
				"provider": self.Type,
				"payload": payload,
			})
			raise ExternalLoginError("Malformed SAML response.")

		if not authn_response.status_ok():
			L.error("SAML authentication failed.", struct_data={
				"provider": self.Type,
			})
			raise ExternalLoginError("SAML authentication failed.")

		user_identity = authn_response.get_identity()
		try:
			user_identity["sub"] = authn_response.get_subject().text
		except ValueError:
			L.error("Cannot infer subject ID from SAML authentication response.", struct_data={
				"provider": self.Type,
			})
			raise ExternalLoginError("Failed to obtain user metadata from SAML response.")

		return user_identity
