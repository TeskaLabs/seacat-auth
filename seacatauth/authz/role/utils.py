import enum
import heapq
import typing


class BoolFieldOp(enum.StrEnum):
	NONE = "none"
	FILTER_TRUE = "filter_true"
	FILTER_FALSE = "filter_false"
	SORT_ASC = "sort_asc"
	SORT_DESC = "sort_desc"
	

def apply_bool_field_op(
	field_name: str,
	bool_field_op: BoolFieldOp,
	filter: dict,
	sort: dict,
):
	"""
	Helper to aggregate boolean field operation into filter and sort dictionaries

	Args:
		field_name: The name of the boolean field
		bool_field_op: The operation to perform on the boolean field
		filter: The filter dictionary to update
		sort: The sort dictionary to update
	"""
	match bool_field_op:
		case BoolFieldOp.FILTER_TRUE:
			filter[field_name] = True
		case BoolFieldOp.FILTER_FALSE:
			filter[field_name] = False
		case BoolFieldOp.SORT_ASC:
			sort[field_name] = 1
		case BoolFieldOp.SORT_DESC:
			sort[field_name] = -1
		case BoolFieldOp.NONE:
			pass
		case _:
			raise ValueError("Unknown BoolFieldOp {!r}".format(bool_field_op))


def role_aggregation_pipeline(
	base_query: dict,
	public_id_expr,
	add_fields: dict,
	filter: dict = None,
	sort: dict = None,
	offset: int = 0,
	limit: int | None = None,
) -> list[dict]:
	"""
	Helper to create a MongoDB aggregation pipeline for role queries

	Args:
		base_query: The base query to match roles
		public_id_expr: The expression to compute the public ID of the role
		add_fields: The fields to add to the documents
		filter: The filter to apply after adding fields
		sort: The sort to apply to the documents
		offset: The number of documents to skip
		limit: The maximum number of documents to return
	"""
	pipeline = [
		{"$match": base_query},
		{"$addFields": {"_public_id": public_id_expr}},
	]
	if add_fields:
		pipeline.append({"$addFields": add_fields})
	if filter:
		pipeline.append({"$match": filter})
	if sort:
		pipeline.append({"$sort": sort})
	else:
		pipeline.append({"$sort": {"_id": 1}})
	if offset:
		pipeline.append({"$skip": offset})
	if limit:
		pipeline.append({"$limit": limit})

	return pipeline


async def amerge_sorted(*iters: typing.AsyncIterable, key: typing.Callable | None = None):
	"""
	Merge multiple sorted async iterables into a single sorted async iterable.

	Args:
		*iters: The async iterables to merge.
		key: Optional key function to extract a comparison key from each element.
			If None, the elements themselves are compared.

	Yields:
		Elements from the input iterables in sorted order.
	"""
	key = key or (lambda x: x)
	heap = []

	# Prime the heap with the first item from each iterator
	aiterators = [aiter(it) for it in iters]
	for idx, iterator in enumerate(aiterators):
		try:
			first = await anext(iterator)
			heap.append((key(first), idx, first, iterator))
		except StopAsyncIteration:
			pass

	heapq.heapify(heap)

	while heap:
		_, idx, value, iterator = heapq.heappop(heap)
		yield value
		try:
			nxt = await anext(iterator)
			heapq.heappush(heap, (key(nxt), idx, nxt, iterator))
		except StopAsyncIteration:
			pass
