import logging
import base64
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.backends
import asab


L = logging.getLogger(__name__)


class BatmanService(asab.Service):
	"""
	Basic Auth Token MANager
	"""

	def __init__(self, app, service_name="seacatauth.BatmanService"):
		super().__init__(app, service_name)

		self.Integrations = []
		key = asab.Config.get("seacatauth:batman", "password_key")
		if key != "":
			self.Key = key.encode("utf-8")
		else:
			# TODO: There should be no hardcoded encryption password
			self.Key = b"12345678901234567890123456789012"

		if "batman:elk" in asab.Config.sections():
			raise ValueError(
				"Config section 'batman:elk' has been renamed to 'batman:elasticsearch'. Please update your config.")

		if "batman:elasticsearch" in asab.Config.sections():
			from .elasticsearch import ElasticSearchIntegration
			self.Integrations.append(
				ElasticSearchIntegration(self)
			)

		if "batman:grafana" in asab.Config.sections():
			from .grafana import GrafanaIntegration
			self.Integrations.append(
				GrafanaIntegration(self)
			)

		app.TaskService.schedule(*[i.initialize() for i in self.Integrations])


	async def initialize(self, app):
		app.PubSub.publish("Batman.initialized!", asynchronously=True)


	def generate_password(self, credentials_id):
		"""
		Generate a basic auth password using credentials ID and configured batman key.
		"""
		digest = cryptography.hazmat.primitives.hashes.Hash(
			cryptography.hazmat.primitives.hashes.SHA256(),
			cryptography.hazmat.backends.default_backend()
		)
		digest.update(credentials_id.encode("utf-8"))
		digest.update(self.Key)
		return base64.b85encode(digest.finalize()).decode("ascii")
