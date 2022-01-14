from .abc import LoginFactorABC


class SubnetFactor(LoginFactorABC):
	Type = "subnet"

	def __init__(self, authn_service, config):
		# TODO: implement subnet login
		super().__init__(authn_service, config)
		raise NotImplementedError()
