import typing
import abc
import re


class RoleView(abc.ABC):
	def __init__(self, storage_service, collection_name):
		self.StorageService = storage_service
		self.CollectionName = collection_name


	@abc.abstractmethod
	async def get(self, role_id: str) -> dict:
		raise NotImplementedError()


	async def count(
		self,
		id_substring: str | None = None,
		description_substring: str | None = None,
		resource_filter: str | None = None,
		flag_tenants: typing.Iterable[str] | None = None,
		tenant_flag_filter: bool | None = None,
		flag_ids: typing.Iterable[str] | None = None,
		id_flag_filter: bool | None = None,
		**kwargs
	) -> int:
		"""
		Count roles matching the given criteria.

		Args:
			id_substring: If given, count only roles whose ID contains this substring.
			description_substring: If given, count only roles whose description contains this substring.
			resource_filter: If given, count only roles with the given resource.
			flag_tenants: If given, add a boolean field "_tenant_flag" indicating whether the role matches any of the given tenants.
			tenant_flag_filter: If given, filter results by the value of the "_tenant_flag" field.
			flag_ids: If given, add a boolean field "_id_flag" indicating whether the role ID is in the given list.
			id_flag_filter: If given, filter results by the value of the "_id_flag" field.
		"""
		pipeline = self._aggregation_pipeline(
			id_substring=id_substring,
			description_substring=description_substring,
			resource_filter=resource_filter,
			flag_tenants=flag_tenants,
			tenant_flag_filter=tenant_flag_filter,
			flag_ids=flag_ids,
			id_flag_filter=id_flag_filter,
			**kwargs
		)
		if pipeline is None:
			return 0

		pipeline.append({"$count": "count"})
		result = await self.StorageService.Database[self.CollectionName].aggregate(pipeline).to_list(length=1)
		if not result:
			return 0

		return result[0]["count"]


	async def iterate(
		self,
		offset: int = 0,
		limit: int | None = None,
		sort: list[tuple[str, int]] | None = None,
		id_substring: str | None = None,
		description_substring: str | None = None,
		resource_filter: str | None = None,
		flag_tenants: typing.Iterable[str] | None = None,
		tenant_flag_filter: bool | None = None,
		flag_ids: typing.Iterable[str] | None = None,
		id_flag_filter: bool | None = None,
		set_fields: dict | None = None,
		**kwargs
	) -> typing.AsyncGenerator:
		"""
		Iterate over roles matching the given criteria.

		Args:
			offset: Number of matching roles to skip.
			limit: Maximum number of matching roles to return.
			sort: If given, sort results by the given field and direction.
			id_substring: If given, return only roles whose ID contains this substring.
			description_substring: If given, return only roles whose description contains this substring.
			resource_filter: If given, return only roles with the given resource.
			flag_tenants: If given, add a boolean field "_tenant_flag" indicating whether the role matches any of the given tenants.
			tenant_flag_filter: If given, filter results by the value of the "_tenant_flag" field.
			flag_ids: If given, add a boolean field "_id_flag" indicating whether the role ID is in the given list.
			id_flag_filter: If given, filter results by the value of the "_id_flag" field.
			set_fields: If given, set the given fields in the final stage.

		Returns:
			An async generator yielding matching roles.
		"""
		pipeline = self._aggregation_pipeline(
			offset=offset,
			limit=limit,
			sort=sort,
			id_substring=id_substring,
			description_substring=description_substring,
			resource_filter=resource_filter,
			flag_tenants=flag_tenants,
			tenant_flag_filter=tenant_flag_filter,
			flag_ids=flag_ids,
			id_flag_filter=id_flag_filter,
			set_fields=set_fields,
			**kwargs
		)
		if pipeline is None:
			return

		cursor = self.StorageService.Database[self.CollectionName].aggregate(pipeline)
		async for role in cursor:
			yield self._normalize_role(role)


	def _aggregation_pipeline(
		self,
		offset: int | None = None,
		limit: int | None = None,
		sort: list[tuple[str, int]] | None = None,
		id_substring: str | None = None,
		description_substring: str | None = None,
		resource_filter: str | None = None,
		flag_tenants: typing.Iterable[str] | None = None,
		tenant_flag_filter: bool | None = None,
		flag_ids: typing.Iterable[str] | None = None,
		id_flag_filter: bool | None = None,
		set_fields: dict | None = None,
		**kwargs
	) -> list[dict] | None:
		"""
		Construct a MongoDB aggregation pipeline for querying roles.

		Args:
			offset: Number of matching roles to skip.
			limit: Maximum number of matching roles to return.
			sort: If given, sort results by the given field and direction.
			id_substring: If given, return only roles whose ID contains this substring.
			description_substring: If given, return only roles whose description contains this substring.
			resource_filter: If given, return only roles with the given resource.
			flag_tenants: If given, add a boolean field "_tenant_flag" indicating whether the role matches any of the given tenants.
			tenant_flag_filter: If given, filter results by the value of the "_tenant_flag" field.
			flag_ids: If given, add a boolean field "_id_flag" indicating whether the role ID is in the given list.
			id_flag_filter: If given, filter results by the value of the "_id_flag" field.
			set_fields: If given, set the given fields in the final stage.

		Returns:
			A list of aggregation pipeline stages, or None if no results are possible.
		"""
		pipeline = []
		base_match = self._base_query()
		if resource_filter:
			base_match["resources"] = resource_filter
		if description_substring:
			base_match["description"] = {"$regex": re.escape(description_substring)}
		pipeline.append({"$match": base_match})

		add_public_id = {"$set": {
			"_public_id": self._public_id_expr(),
			"description": {"$ifNull": ["$description", ""]}
		}}
		pipeline.append(add_public_id)

		add_fields = {}
		second_match = {}

		if id_substring:
			second_match["_public_id"] = {"$regex": re.escape(id_substring)}

		if flag_tenants:
			is_tenant_match = self._is_tenant_match(flag_tenants)
			if tenant_flag_filter is not None:
				if is_tenant_match != tenant_flag_filter:
					# No results possible
					return
				else:
					# All results possible, sorting has no effect
					pass
			add_fields["_tenant_flag"] = is_tenant_match

		if flag_ids:
			add_fields["_id_flag"] = {
				"$in": ["$_public_id", flag_ids]
			}
			if id_flag_filter is not None:
				second_match["_id_flag"] = id_flag_filter

		if add_fields:
			pipeline.append({"$addFields": add_fields})

		if second_match:
			pipeline.append({"$match": second_match})

		if sort:
			pipeline.append({"$sort": {k: v for k, v in sort}})

		if offset:
			pipeline.append({"$skip": offset})

		if limit:
			pipeline.append({"$limit": limit})

		if set_fields:
			pipeline.append({"$addFields": set_fields})

		return pipeline


	@abc.abstractmethod
	def _base_query(self) -> dict:
		raise NotImplementedError()


	def _public_id_expr(self):
		return "$_id"


	@abc.abstractmethod
	def _is_tenant_match(self, tenants: typing.Iterable[str]) -> bool:
		raise NotImplementedError


	@abc.abstractmethod
	def _role_tenant_matches(self, role_id: str):
		raise NotImplementedError()


	def _normalize_role(self, role: dict):
		if role.get("managed_by"):
			role["read_only"] = True
		return role
