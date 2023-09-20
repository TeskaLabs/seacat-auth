import logging
from typing import Optional

import asab.storage.mongodb
import asab.storage.exceptions

from .abc import EditableTenantsProviderABC

from ...events import EventTypes

#

L = logging.getLogger(__name__)

#


class MongoDBTenantProvider(EditableTenantsProviderABC):

	Type = "mongodb"

	ConfigDefaults = {
		'tenant_collection': 't',
		'assign_collection': 'ct',
	}

	def __init__(self, app, provider_id, config_section_name):
		super().__init__(provider_id, config_section_name)

		self.App = app
		self.MongoDBStorageService = asab.storage.mongodb.StorageService(
			app,
			"seacatauth.tenant.mongodb.{}.storage".format(provider_id),
			config_section_name=config_section_name
		)

		self.TenantsCollection = self.Config['tenant_collection']
		self.AssignCollection = self.Config['assign_collection']


	async def iterate(self, page: int = 1, limit: int = None, filter: str = None):
		collection = await self.MongoDBStorageService.collection(self.TenantsCollection)

		if filter is None:
			cursor = collection.find()
			cursor.sort("_id", 1)
			if limit is not None:
				cursor.skip(limit * page)
				cursor.limit(limit)
		else:
			# Fetch tenants that contain `filter` substring
			# Sort results so that tenants that start with the substring come first
			pipeline = [
				# Set "_match" to:
				#  -1 if tenant does not contain substring
				#   0 if tenant starts with substring
				#   1 if tenant contains substring but not at the start
				{"$addFields": {"_match": {"$min": [
					{"$indexOfCP": [{"$toLower": "$_id"}, filter.lower()]}, 1
				]}}},
				# Exclude tenants that do not contain substring at all
				{"$match": {"$expr": {"$gte": ["$_match", 0]}}},
				# Sort matches so that tenants that start with substring come first
				# Secondary sort is alphabetical
				{"$sort": {"_match": 1, "_id": 1}},
			]
			if limit is not None:
				pipeline.append({"$skip": limit * page})
				pipeline.append({"$limit": limit})
			cursor = collection.aggregate(pipeline)

		async for tenant in cursor:
			yield tenant


	async def count(self, filter=None) -> int:
		coll = await self.MongoDBStorageService.collection(self.TenantsCollection)

		if filter is not None:
			# Count only entries that contain `filter` substring
			filter = {"$expr": {"$gte": [{"$indexOfCP": [{"$toLower": "$_id"}, filter.lower()]}, 0]}}
		else:
			filter = {}
		return await coll.count_documents(filter=filter)


	async def create(self, tenant_id: str, creator_id: str = None) -> Optional[str]:
		u = self.MongoDBStorageService.upsertor(self.TenantsCollection, obj_id=tenant_id, version=0)
		if creator_id is not None:
			u.set("created_by", creator_id)
		tenant_id = await u.execute()
		L.log(asab.LOG_NOTICE, "Tenant created", struct_data={"tenant": tenant_id})
		return tenant_id


	async def update(self, tenant_id: str, *, description: str = None, data: dict = None) -> Optional[str]:
		tenant = await self.get(tenant_id)
		u = self.MongoDBStorageService.upsertor(
			self.TenantsCollection,
			obj_id=tenant_id,
			version=tenant["_v"]
		)
		if description is not None:
			u.set("description", description)
		if data is not None:
			u.set("data", data)
		tenant_id = await u.execute()

		L.log(asab.LOG_NOTICE, "Tenant data updated.", struct_data={"tenant": tenant_id})
		return "OK"


	async def delete(self, tenant_id: str) -> Optional[bool]:
		"""
		Delete tenant. Also delete all its roles and assignments.
		"""
		await self.MongoDBStorageService.delete(self.TenantsCollection, tenant_id)
		L.log(asab.LOG_NOTICE, "Tenant deleted.", struct_data={"tenant": tenant_id})


	async def get(self, tenant_id) -> Optional[dict]:
		# Fetch the tenant from a Mongo
		tenant = await self.MongoDBStorageService.get(
			self.TenantsCollection,
			# bson.ObjectId(tenant_id)
			tenant_id
		)

		return tenant


	# async def register(self, register_info, credentials_id):
	# 	tenant_provider = self.TenantService.get_provider()

	# 	# tenant
	# 	if 'tenant' in register_info:
	# 		tenant = register_info.get('tenant')
	# 	elif 'tenant' in register_info['features']:
	# 		tenant = register_info["request"].get("tenant")
	# 		tenant_result = await tenant_provider.create_tenant(tenant)
	# 		if tenant_result is None:
	# 			print("Tenant already exists.")
	# 			return
	# 	else:
	# 		L.warning("Register info does not contain tenant name.")
	# 		return

	# 	# tenant assignment
	# 	tenant_assignment = await tenant_provider.assign_tenant(credentials_id, tenant)
	# 	return tenant_assignment


	async def iterate_assigned(self, credatials_id: str, page: int = 10, limit: int = None):
		collection = await self.MongoDBStorageService.collection(self.AssignCollection)

		filter = {'c': credatials_id}
		cursor = collection.find(filter)

		cursor.sort('_id', 1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		async for obj in cursor:
			yield obj


	async def assign_tenant(self, credentials_id: str, tenant: str):
		"""
		Assign tenant to credentials
		"""
		assignment_id = "{} {}".format(credentials_id, tenant)
		upsertor = self.MongoDBStorageService.upsertor(self.AssignCollection, obj_id=assignment_id)
		upsertor.set("c", credentials_id)
		upsertor.set("t", tenant)
		await upsertor.execute(event_type=EventTypes.TENANT_ASSIGNED)


	async def unassign_tenant(self, credentials_id: str, tenant: str):
		"""
		Unassign credentials from tenant
		"""
		assignment_id = "{} {}".format(credentials_id, tenant)
		await self.MongoDBStorageService.delete(self.AssignCollection, obj_id=assignment_id)

		L.log(asab.LOG_NOTICE, "Tenant successfully unassigned from credentials", struct_data={
			"cid": credentials_id,
			"tenant": tenant,
		})


	async def list_tenant_assignments(self, tenant, page: int = 0, limit: int = None):
		query_filter = {'t': tenant}
		collection = await self.MongoDBStorageService.collection(self.AssignCollection)
		cursor = collection.find(query_filter)

		cursor.sort("_c", -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		assignments = []
		async for assignment in cursor:
			assignments.append(assignment)

		return {
			"data": assignments,
			"count": await collection.count_documents(query_filter)
		}


	async def delete_tenant_assignments(self, tenant):
		collection = await self.MongoDBStorageService.collection(self.AssignCollection)
		result = await collection.delete_many({"t": tenant})

		L.log(asab.LOG_NOTICE, "Tenant unassigned", struct_data={
			"tenant": tenant,
			"deleted_count": result.deleted_count
		})


	async def get_assignment(self, credatials_id: str, tenant: str):
		collection = await self.MongoDBStorageService.collection(self.AssignCollection)
		query = {"c": credatials_id, "t": tenant}
		result = await collection.find_one(query)
		if result is None:
			raise KeyError("Tenant assignment not found")
		return result
