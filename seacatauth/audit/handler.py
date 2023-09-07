import datetime
import logging

import asab
import asab.utils
import asab.web.rest

from seacatauth.decorators import access_control

#

L = logging.getLogger(__name__)

#


class AuditHandler(object):
	"""
	Audit management

	---
	tags: ["Audit management"]
	"""

	def __init__(self, app, audit_service):
		self.AuditService = audit_service

		web_app = app.WebContainer.WebApp
		web_app.router.add_put("/audit/prune", self.prune_old_audit_entries)

	@asab.web.rest.json_schema_handler({
		"type": "object",
		"additionalProperties": False,
		"properties": {
			"max_age": {
				"oneOf": [
					{"type": "string"},
					{"type": "number"}],
				"description":
					"Duration string or number of seconds specifying the maximum age of audit entries "
					"which will be retained."}}
	})
	@access_control("authz:superuser")
	async def prune_old_audit_entries(self, request, *, json_data):
		"""
		Delete audit entries older than specified age.
		"""
		max_age = asab.utils.convert_to_seconds(json_data["max_age"])
		before_datetime = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=max_age)
		deleted_count = await self.AuditService.delete_old_entries(before_datetime)
		return asab.web.rest.json_response(request, {
			"result": "OK", "count": deleted_count})
