import typing
import abc
import re

from ..utils import BoolFieldOp, apply_bool_field_op, role_aggregation_pipeline


class RoleView(abc.ABC):
	def __init__(self, storage_service, collection_name):
		self.StorageService = storage_service
		self.CollectionName = collection_name


	@abc.abstractmethod
	async def get(self, role_id: str) -> dict:
		raise NotImplementedError()


	async def count(
		self,
		name_filter: str | None = None,
		resource_match: typing.Tuple[str, BoolFieldOp] | None = None,
		tenant_match: typing.Tuple[typing.Iterable[str], BoolFieldOp] | None = None,
		id_match: typing.Tuple[typing.Iterable[str], BoolFieldOp] | None = None,
		**kwargs
	) -> int:
		"""
		Count roles matching the given criteria.

		Args:
			name_filter: If given, only roles whose ID matches this regex are counted.
			resource_match: If given, only roles with (or without) the given resource are counted.
			tenant_match: If given, only roles matching (or not matching) the given tenants are counted.
			id_match: If given, only roles matching (or not matching) the given IDs are counted.
		"""
		base_query = self._base_query()
		if name_filter:
			base_query["_id"] = {"$regex": re.escape(name_filter)}
		add_fields = {}
		filter = {}
		sort = {}

		if tenant_match:
			try:
				self._apply_tenant_match(tenant_match, add_fields, filter, sort)
			except StopIteration:
				# No results pass through the filter
				return 0

		if resource_match:
			self._apply_resource_match(resource_match, add_fields, filter, sort)

		if id_match:
			self._apply_id_match(id_match, add_fields, filter, sort)

		count_pipeline = role_aggregation_pipeline(
			base_query=base_query,
			public_id_expr=self._public_id_expr(),
			add_fields=add_fields,
			filter=filter,
		)
		count_pipeline.append({"$count": "count"})
		count = await self.StorageService.Database[self.CollectionName].aggregate(count_pipeline).to_list(length=1)
		if not count:
			return 0

		return count[0]["count"]


	async def iterate(
		self,
		offset: int = 0,
		limit: int | None = None,
		sort: list[tuple[str, str]] | None = None,
		name_filter: str | None = None,
		resource_match: typing.Tuple[str, BoolFieldOp] | None = None,
		tenant_match: typing.Tuple[typing.Iterable[str], BoolFieldOp] | None = None,
		id_match: typing.Tuple[typing.Iterable[str], BoolFieldOp] | None = None,
		**kwargs
	) -> typing.AsyncGenerator:
		"""
		Iterate over roles matching the given criteria.

		Args:
			offset: Number of matching roles to skip.
			limit: Maximum number of matching roles to return.
			sort: If given, sort results by the given field and direction.
			name_filter: If given, only roles whose ID matches this regex are returned.
			resource_match: If given, only roles with (or without) the given resource are returned.
			tenant_match: If given, only roles matching (or not matching) the given tenants are returned.
			id_match: If given, only roles matching (or not matching) the given IDs are returned.
		"""
		base_query = self._base_query()
		add_fields = {}
		filter = {}
		_sort = {}
		if sort:
			for field, direction in sort:
				if direction == "a":
					_sort[field] = 1
				elif direction == "d":
					_sort[field] = -1
				else:
					raise ValueError("Invalid sort direction: {}".format(direction))

		if name_filter:
			filter["_public_id"] = {"$regex": re.escape(name_filter)}

		if tenant_match:
			try:
				self._apply_tenant_match(tenant_match, add_fields, filter, _sort)
			except StopIteration:
				# No results pass through the filter
				return

		if resource_match:
			self._apply_resource_match(resource_match, add_fields, filter, _sort)

		if id_match:
			self._apply_id_match(id_match, add_fields, filter, _sort)

		pipeline = role_aggregation_pipeline(
			base_query=base_query,
			public_id_expr=self._public_id_expr(),
			add_fields=add_fields,
			filter=filter,
			sort=_sort,
			offset=offset,
			limit=limit,
		)

		cursor = self.StorageService.Database[self.CollectionName].aggregate(pipeline)
		async for role in cursor:
			yield self._normalize_role(role)


	@abc.abstractmethod
	def _base_query(self) -> dict:
		raise NotImplementedError()


	def _public_id_expr(self):
		return "$_id"


	@abc.abstractmethod
	def _apply_tenant_match(
		self,
		tenant_match: typing.Tuple[typing.Iterable[str], BoolFieldOp],
		add_fields: dict,
		filter: dict,
		sort: dict,
	):
		raise NotImplementedError()


	def _apply_id_match(
		self,
		id_match: typing.Tuple[typing.Iterable[str], BoolFieldOp],
		add_fields: dict,
		filter: dict,
		sort: dict,
	):
		add_fields["id_match"] = {
			"$in": ["$_public_id", list(id_match[0])]
		}
		apply_bool_field_op("id_match", id_match[1], filter, sort)


	def _apply_resource_match(
		self,
		resource_match: typing.Tuple[typing.Iterable[str], BoolFieldOp],
		add_fields: dict,
		filter: dict,
		sort: dict,
	):
		add_fields["resource_match"] = {
			"$in": [resource_match[0], "$resources"]
		}
		apply_bool_field_op("resource_match", resource_match[1], filter, sort)


	@abc.abstractmethod
	def _role_tenant_matches(self, role_id: str):
		raise NotImplementedError()


	def _normalize_role(self, role: dict):
		if role.get("managed_by"):
			role["read_only"] = True
		return role
