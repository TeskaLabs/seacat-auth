import json
import logging
import re
import fastjsonschema
import asab.contextvars

from ..models.const import ResourceId
from .schema import USERNAME_PATTERN


L = logging.getLogger(__name__)


class CredentialsPolicy:
	PolicySchema = {
		"definitions": {
			"creation_options": {
				"type": "string",
				"enum": ["required", "allowed", "disabled"],
			},
			"edit_options": {
				"type": "string",
				"enum": ["anybody", "admin_only", "nobody"],
			},
		},
		"type": "object",
		"additionalProperties": False,
		"properties": {
			"username": {
				"type": "object",
				"default": {
					"creation": "required",
					"registration": "required",
					"editable_by": "nobody",
				},
				"properties": {
					"creation": {"$ref": "#/definitions/creation_options"},
					"registration": {"$ref": "#/definitions/creation_options"},
					"editable_by": {
						"type": "string",
						"enum": ["nobody"],  # Username editing might be allowed for superuser only
					},
				},
			},
			"email": {
				"type": "object",
				"default": {
					"creation": "allowed",
					"registration": "required",
					"editable_by": "anybody",
				},
				"properties": {
					"creation": {"$ref": "#/definitions/creation_options"},
					"registration": {"$ref": "#/definitions/creation_options"},
					"editable_by": {"$ref": "#/definitions/edit_options"},
				},
			},
			"phone": {
				"type": "object",
				"default": {
					"creation": "allowed",
					"registration": "allowed",
					"editable_by": "anybody",
				},
				"properties": {
					"creation": {"$ref": "#/definitions/creation_options"},
					"registration": {"$ref": "#/definitions/creation_options"},
					"editable_by": {"$ref": "#/definitions/edit_options"},
				},
			},
		},
	}


	def __init__(self, rbac_svc, policy_file):
		self.RBACService = rbac_svc

		self.Policy = {}
		self.CreationPolicy = {}
		self.RegistrationPolicy = {}
		self.UpdatePolicy = {}
		self.M2MCreationPolicy = {
			"username": "required",
			"password": "required",  # At this moment password is the only login option
		}

		self._load_policy(policy_file)


	def _load_policy(self, policy_file):
		"""
		Read provider policy from JSON file.
		If no file is specified, use default policy defined in schema.
		"""
		if policy_file != "":
			with open(policy_file) as f:
				policy = json.load(f)
		else:
			policy = {}

		validate = fastjsonschema.compile(self.PolicySchema)
		self.Policy = validate(policy)

		# Extract creation, registration, editable and ident attributes
		for attribute, attribute_policy in self.Policy.items():
			if attribute_policy["creation"] != "disabled":
				self.CreationPolicy[attribute] = attribute_policy["creation"]
			if attribute_policy["registration"] != "disabled":
				self.RegistrationPolicy[attribute] = attribute_policy["registration"]
			if attribute_policy["editable_by"] != "nobody":
				self.UpdatePolicy[attribute] = attribute_policy["editable_by"]


	def _validate_credentials_data(self, credentials_data: dict, policy: dict):
		validated_data = {}
		for field, policy in policy.items():
			value = credentials_data.pop(field, None)
			if value is not None and len(value) > 0:
				# TODO: Systematic value checking of other fields
				if field == "username" and not re.fullmatch(USERNAME_PATTERN, value):
					L.error(
						"Cannot create credentials: Invalid username",
						struct_data={"username": value}
					)
					return None
				validated_data[field] = value
			else:
				# Field not provided
				if policy == "required":
					L.error(
						"Cannot create credentials: Missing field",
						struct_data={"field": field, "policy": policy}
					)
					return None
				elif policy == "allowed":
					continue
				else:
					raise RuntimeError("Unknown policy: {}".format(policy))

		# Assert there are no extra fields
		if len(credentials_data) > 0:
			L.error(
				"Cannot create credentials: Excess fields",
				struct_data={"fields": " ".join(credentials_data.keys())}
			)
			return None

		return validated_data


	def validate_creation_data(self, creation_data: dict):
		validated_data = self._validate_credentials_data(creation_data, self.CreationPolicy)
		if validated_data is None:
			return None
		# At least one of (phone, email) must be specified
		if not (validated_data.get("email") or validated_data.get("phone")):
			L.error(
				"Cannot create credentials: Phone or email must be specified",
				struct_data={"credentials": validated_data})
			return None
		return validated_data


	def validate_m2m_creation_data(self, creation_data: dict):
		return self._validate_credentials_data(creation_data, self.M2MCreationPolicy)


	def validate_registration_data(self, registration_data: dict):
		return self._validate_credentials_data(registration_data, self.RegistrationPolicy)


	def _can_update(self, credentials_id: str, attribute):
		authz = asab.contextvars.Authz.get()

		# Credentials suspension is always allowed for admins only
		if attribute == "suspended":
			return authz.has_resource_access(ResourceId.CREDENTIALS_EDIT)

		policy = self.UpdatePolicy.get(attribute)

		if policy is None:
			return False

		elif policy == "admin_only":
			return authz.has_resource_access(ResourceId.CREDENTIALS_EDIT)

		elif policy == "anybody":
			if authz.has_resource_access(ResourceId.CREDENTIALS_EDIT):
				return True
			elif credentials_id == authz.CredentialsId:
				return True
			else:
				return False

		else:
			L.error("Invalid policy value", struct_data={"attribute": attribute, "policy": policy})
			return False


	def validate_update_data(self, credentials_id: str, update_data: dict):
		for field in update_data:
			if not self._can_update(credentials_id, field):
				L.error("Cannot update credentials: Field update not permitted", struct_data={
					"field": field,
				})
				return None
			if update_data.get("email") == "" and update_data.get("phone") == "":
				L.error("Credentials update failed: Cannot unset both email and phone")
				return None
		return update_data
