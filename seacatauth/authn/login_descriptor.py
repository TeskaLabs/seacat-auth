import logging
import typing
import asab

from .login_factors import LoginFactorABC

#

L = logging.getLogger(__name__)

#


class LoginDescriptor:
	"""
	A LoginDescriptor represents one complete login option.
	To get authenticated, one must pass all the factors in a chosen login descriptor.
	"""
	@classmethod
	def build(cls, authn_svc, descriptor_config):
		ldid = descriptor_config.pop("id")
		label = descriptor_config.pop("label")
		factors_config = descriptor_config.pop("factors")
		data = descriptor_config

		if len(factors_config) == 0:
			raise ValueError("No login factors specified in descriptor {!r}".format(ldid))

		if not isinstance(factors_config[0], list):
			# There is only one OR-group. Nest it to preserve schema.
			factors_config = [factors_config]

		# There are several OR-groups of login factors
		factor_groups = []
		for config_group in factors_config:
			group = []
			for config in config_group:
				try:
					factor = authn_svc.get_login_factor(config["type"])
				except KeyError:
					factor = authn_svc.create_login_factor(config)
				group.append(factor)
			factor_groups.append(group)

		return LoginDescriptor(ldid, label, factor_groups, data)

	def __init__(self, id, label, factors, data):
		self.ID: str = id
		self.Label: typing.Union[str, dict] = label
		self.Data: dict = data
		self.FactorGroups: typing.List[typing.List[LoginFactorABC]] = factors

	def __repr__(self):
		return "LoginDescriptor[{}]".format(
			str({
				"id": self.ID,
				"label": self.Label,
				"factors": self.FactorGroups,
				**self.Data
			})
		)

	async def login_prologue(self, login_data, login_preferences=None):
		"""
		Checks the eligibility of this LoginDescriptor's login factors and
		returns either a new LoginDescriptor with only one LoginFactor group,
		or None if no LoginFactor group is eligible.

		:param login_data: Contains "credentials_id" and other login information that may be needed by login factors.
		:param login_preferences: List of preferred LoginDescriptor ID's.
		"""
		# If URL login preferences are specified, check if descriptor id is listed there
		if login_preferences is not None and self.ID not in login_preferences:
			return None

		# Check eligible login factors
		for group in self.FactorGroups:
			# For a group to pass, all factors in the group must be eligible
			for factor in group:
				if not await factor.is_eligible(login_data):
					break
			else:
				# Once an eligible group is found, the search stops and the group is passed in the result
				eligible_factor_group = group
				break
		else:
			# No eligible group was found
			return None

		return LoginDescriptor(
			id=self.ID,
			label=self.Label,
			factors=[eligible_factor_group],
			data=self.Data
		)

	async def authenticate(self, login_session, request_data):
		"""
		Checks if the login session is authenticated with all of this LoginDescriptor's factors
		"""
		# At the authentication stage, there should be exactly one factor group
		assert len(self.FactorGroups) == 1
		for factor in self.FactorGroups[0]:
			if (await factor.authenticate(login_session, request_data)) is False:
				L.log(asab.LOG_NOTICE, "Login factor verification failed.", struct_data={
					"descriptor_id": self.ID,
					"factor_type": factor.Type,
					"cid": login_session.CredentialsId,
				})
				return False
		return True

	def serialize(self):
		# Flatten the factor group if there is only one (for UI compatibility)
		if len(self.FactorGroups) == 1:
			return {
				"id": self.ID,
				"label": self.Label,
				"factors": [
					factor.serialize()
					for group in self.FactorGroups
					for factor in group
				],
				**self.Data
			}
		else:
			return {
				"id": self.ID,
				"label": self.Label,
				"factors": [
					[
						factor.serialize()
						for factor in group
					]
					for group in self.FactorGroups
				],
				**self.Data
			}

	@classmethod
	def deserialize(cls, authn_svc, data: dict):
		ldid = data.pop("id")
		label = data.pop("label")
		factors_config = data.pop("factors")

		if not isinstance(factors_config[0], list):
			factors_config = [factors_config]

		factors = [
			[
				authn_svc.get_login_factor(factor["type"])
				for factor in group
			]
			for group in factors_config
		]

		return cls(ldid, label, factors, data)
