import heapq
import typing


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
