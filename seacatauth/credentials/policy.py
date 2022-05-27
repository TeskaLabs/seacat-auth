import json
import logging
import re

import fastjsonschema

from .schemas import USERNAME_PATTERN

#

L = logging.getLogger(__name__)

#


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
			"username": {"creation": "required"},
			"password": {"creation": "required"},  # At this moment password is the only login option
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
		# At least one of (phone, email) must be specified
		if not (validated_data.get("email") or validated_data.get("phone")):
			L.error(
				"Cannot create credentials: Phone or email must be specified",
				struct_data={
					"username": validated_data["username"],
					"phone": validated_data["phone"]
				}
			)
			return None
		# Assert there are no extra fields
		if len(credentials_data) > 0:
			L.error(
				"Cannot create credentials: Excess fields",
				struct_data={"fields": " ".join(credentials_data.keys())}
			)
			return None

		return validated_data

	def validate_creation_data(self, creation_data: dict):
		return self._validate_credentials_data(creation_data, self.CreationPolicy)

	def validate_m2m_creation_data(self, creation_data: dict):
		return self._validate_credentials_data(creation_data, self.M2MCreationPolicy)

	def validate_registration_data(self, registration_data: dict):
		return self._validate_credentials_data(registration_data, self.RegistrationPolicy)

	def _can_update(self, attribute, authz=None):
		# Credentials suspension is always allowed for admins only
		if attribute == "suspended":
			if authz is None:
				return False
			return self.RBACService.has_resource_access(
				authz,
				tenant="*",
				requested_resources=["authz:superuser"],
			) == "OK"

		policy = self.UpdatePolicy.get(attribute)

		if policy is None:
			return False

		elif policy == "anybody":
			return True

		elif policy == "admin_only":
			if authz is None:
				return False
			return self.RBACService.has_resource_access(
				authz,
				tenant="*",
				requested_resources=["authz:superuser"],
			) == "OK"

		# TODO: Check configurable resource-based policy
		else:
			L.error("Invalid policy value", struct_data={"attribute": attribute, "policy": policy})
			return False

	def validate_update_data(self, update_data: dict, authz: dict):
		for field in update_data:
			if not self._can_update(field, authz):
				L.error("Cannot update credentials: Field update not permitted", struct_data={
					"field": field,
				})
				return None
			if not (update_data.get("email") or update_data.get("phone")):
				L.error(
					"Cannot create credentials: Phone or email must be specified",
					struct_data={
						"username": update_data["username"],
						"phone": update_data["phone"]}
				)
				return None
		return update_data
