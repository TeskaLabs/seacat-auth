from .abc import LoginFactorABC
from .password import PasswordFactor
from .smscode import SMSCodeFactor
from .totp import TOTPFactor
from .subnet import SubnetFactor
from .xheader import XHeaderFactor

import logging
L = logging.getLogger(__name__)


def login_factor_builder(authn_service, factor_config):
	"""
	Creates an instance of the correct login factor class
	"""
	factor_type = factor_config["type"]
	if factor_type == "password":
		return PasswordFactor(authn_service=authn_service, config=factor_config)

	elif factor_type == "smscode":
		return SMSCodeFactor(authn_service=authn_service, config=factor_config)

	elif factor_type == "smslogin":
		L.warning("Factor type 'smslogin' will be deprecated. Use 'smscode' instead.")
		return SMSCodeFactor(authn_service=authn_service, config=factor_config)

	elif factor_type == "totp":
		return TOTPFactor(authn_service=authn_service, config=factor_config)

	elif factor_type == "subnet":
		return SubnetFactor(authn_service=authn_service, config=factor_config)

	elif factor_type == "xheader":
		return XHeaderFactor(authn_service=authn_service, config=factor_config)

	raise ValueError("Unknown login factor type: {}".format(factor_type))


__all__ = [
	"LoginFactorABC",
	"PasswordFactor",
	"SMSCodeFactor",
	"TOTPFactor",
	"SubnetFactor",
	"XHeaderFactor",
	"login_factor_builder"
]
