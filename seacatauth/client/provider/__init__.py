from .abc import ClientProviderABC
from .mongodb import MongoDBClientProvider


def get_provider_by_type(provider_type: str) -> type[ClientProviderABC] | None:
	if provider_type == MongoDBClientProvider.Type:
		return MongoDBClientProvider
	return None


__all__ = [
	"ClientProviderABC",
	"MongoDBClientProvider",
	"get_provider_by_type"
]
