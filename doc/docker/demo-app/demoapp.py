import aiohttp.web
import asab
import asab.web.rest
import asab.web.authz


class DemoApplication(asab.Application):
	def __init__(self):
		super().__init__()

		# Initialize web
		self.add_module(asab.web.Module)
		websvc = self.get_service("asab.WebService")
		container = asab.web.WebContainer(websvc, "web")

		# Enable translation of python errors to JSON responses
		container.WebApp.middlewares.append(asab.web.rest.JsonExceptionMiddleware)

		# Add auth middleware
		authz_service = asab.web.authz.AuthzService(self)
		container.WebApp.middlewares.append(
			asab.web.authz.authz_middleware_factory(self, authz_service)
		)

		container.WebApp.router.add_get("", self.welcome)
		container.WebApp.router.add_get("/", self.welcome)


	@asab.web.authz.userinfo_handler
	async def welcome(self, request, *, userinfo):
		body = """
		<!DOCTYPE html>
		<html>
		<head>
			<title>SeaCat Auth Demo</title>
		</head>
		<body>
			<h1>Hi {username}!</h1>
			<p>Welcome to demo ASAB application, you have successfully logged in!</p>
		</body>
		</html>
		""".format(
			username=userinfo.get("preferred_username")
		).strip()
		return aiohttp.web.Response(body=body, content_type="text/html")


if __name__ == "__main__":
	app = DemoApplication()
	app.run()
