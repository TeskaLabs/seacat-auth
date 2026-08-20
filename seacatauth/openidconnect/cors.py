import aiohttp.web


ALLOWED_METHODS = "GET, POST, PUT, OPTIONS"
ALLOWED_HEADERS = "Authorization, Content-Type, X-App, X-Request-Id"
PREFLIGHT_MAX_AGE = "86400"

_OAUTH_WELL_KNOWN_PATHS = frozenset({
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/.well-known/jwks.json",
	"/.well-known/oauth-protected-resource",
})


def is_oauth_api_path(path: str) -> bool:
	if path.startswith("/openidconnect/"):
		return True
	if path in _OAUTH_WELL_KNOWN_PATHS:
		return True
	return path.startswith("/.well-known/oauth-protected-resource/")


def oauth_cors_headers(origin: str) -> dict:
	return {
		"Access-Control-Allow-Origin": origin,
		"Access-Control-Allow-Credentials": "true",
		"Access-Control-Allow-Methods": ALLOWED_METHODS,
		"Access-Control-Allow-Headers": ALLOWED_HEADERS,
		"Access-Control-Max-Age": PREFLIGHT_MAX_AGE,
		"Vary": "Origin",
	}


def apply_oauth_cors_headers(request, response, client_service) -> None:
	if not is_oauth_api_path(request.path):
		return
	origin = request.headers.get("Origin")
	if not origin or not client_service.is_origin_allowed(origin):
		return
	for key, value in oauth_cors_headers(origin).items():
		response.headers[key] = value


async def _preflight_handler(request):
	return aiohttp.web.HTTPNoContent()


def install_oauth_cors(web_app: aiohttp.web.Application, client_service) -> None:
	async def _on_prepare_response(request, response):
		apply_oauth_cors_headers(request, response, client_service)

	web_app.on_response_prepare.append(_on_prepare_response)
	web_app.router.add_route("OPTIONS", "/openidconnect/{tail:.*}", _preflight_handler)
	web_app.router.add_route("OPTIONS", "/.well-known/openid-configuration", _preflight_handler)
	web_app.router.add_route("OPTIONS", "/.well-known/oauth-authorization-server", _preflight_handler)
	web_app.router.add_route("OPTIONS", "/.well-known/jwks.json", _preflight_handler)
	web_app.router.add_route("OPTIONS", "/.well-known/oauth-protected-resource", _preflight_handler)
	web_app.router.add_route(
		"OPTIONS", "/.well-known/oauth-protected-resource/{resource:.*}", _preflight_handler)
