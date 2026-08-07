import typing

import logging
import asab
import asab.contextvars
import asab.log


def audit_struct_data(extra: typing.Optional[dict] = None) -> dict:
	"""
	Build a base struct_data dict for audit logs, enriched from the ASAB
	Request, Authz, and Tenant context variables.

	Safe to call from system-initiated code that has not set these context variables.
	Caller-provided values take precedence over inferred values.

	Enriched fields:
	- ``from_ip``: extracted from the request using ``generic.get_request_access_ips``.
	- ``agent_cid``: from ``Authz.CredentialsId``.
	- ``agent_sid``: from ``Authz.SessionId``.
	- ``superuser``: ``True`` if the agent has superuser access.
	- ``tenant``: from the current tenant context.
	"""
	# Import lazily to avoid circular imports during module load
	from . import generic

	struct_data = {}

	try:
		request = asab.contextvars.Request.get()
	except LookupError:
		request = None

	if request is not None:
		struct_data["from_ip"] = generic.get_request_access_ips(request)

	try:
		authz = asab.contextvars.Authz.get()
	except LookupError:
		authz = None

	if authz is not None:
		if authz.CredentialsId is not None:
			struct_data["agent_cid"] = authz.CredentialsId
		if authz.SessionId is not None:
			struct_data["agent_sid"] = authz.SessionId
		if authz.has_superuser_access():
			struct_data["superuser"] = True

	try:
		tenant = asab.contextvars.Tenant.get()
	except LookupError:
		tenant = None

	if tenant is not None:
		struct_data["tenant"] = tenant

	if extra:
		struct_data.update(extra)

	return struct_data


class AuditLogger(asab.log._StructuredDataLogger):
	"""
	Audit logger that automatically enriches every ``struct_data`` dict with
	request, authorization, and tenant context.

	Both the low-level ``log()`` method and the convenience methods
	(``notice()``, ``warning()``, ``error()``, ``exception()``) enrich the
	``struct_data`` before passing it to the underlying Python logger.
	"""

	def log(self, level, msg, *args, struct_data=None, **kwargs):
		return super().log(
			level, msg, *args,
			struct_data=audit_struct_data(struct_data),
			**kwargs
		)

	def notice(self, msg, *args, struct_data=None, **kwargs):
		return self.log(asab.LOG_NOTICE, msg, *args, struct_data=struct_data, **kwargs)

	def warning(self, msg, *args, struct_data=None, **kwargs):
		return self.log(logging.WARNING, msg, *args, struct_data=struct_data, **kwargs)

	def error(self, msg, *args, struct_data=None, **kwargs):
		return self.log(logging.ERROR, msg, *args, struct_data=struct_data, **kwargs)

	def exception(self, msg, *args, struct_data=None, exc_info=True, **kwargs):
		return self.log(logging.ERROR, msg, *args, exc_info=exc_info, struct_data=struct_data, **kwargs)
