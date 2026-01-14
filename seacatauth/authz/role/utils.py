import heapq
import typing


async def amerge_sorted(
	*iters: typing.AsyncIterable,
	key: typing.Callable | None = None,
	offset: int | None = 0,
	limit: int | None = None
) -> typing.AsyncIterable:
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

	i = 0
	while heap:
		_, idx, value, iterator = heapq.heappop(heap)
		if i > offset:
			yield value
		try:
			nxt = await anext(iterator)
			heapq.heappush(heap, (key(nxt), idx, nxt, iterator))
		except StopAsyncIteration:
			pass
		i += 1
		if limit and i >= (offset or 0) + limit:
			break


class ReverseSortingString(str):
	"""
	Helper class to invert string comparison for sorting in descending order
	"""
	def __lt__(self, other):
		return str.__gt__(self, other)
	def __le__(self, other):
		return str.__ge__(self, other)
	def __gt__(self, other):
		return str.__lt__(self, other)
	def __ge__(self, other):
		return str.__le__(self, other)
