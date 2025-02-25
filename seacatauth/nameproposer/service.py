import logging
import random

import asab

from .animals import ANIMALS
from .adjectives import ADJECTIVES


L = logging.getLogger(__name__)


class NameProposerService(asab.Service):


	def __init__(self, app, service_name='seacatauth.NameProposerService'):
		super().__init__(app, service_name)

	def propose_name(self):
		adjective = random.choice(ADJECTIVES)
		animal = random.choice(ANIMALS)
		tenant_name = "{}{}".format(adjective, animal).lower()
		return tenant_name
