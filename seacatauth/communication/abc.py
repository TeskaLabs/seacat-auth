import abc
import logging

import asab

#

L = logging.getLogger(__name__)

#


class CommunicationProviderABC(asab.Configurable, abc.ABC):

	Channel = None

	def __init__(self, provider_id, config_section_name, config=None):
		self.Id = provider_id
		super().__init__(config_section_name=config_section_name, config=config)

	async def send_message(self, **kwargs):
		raise NotImplementedError()
