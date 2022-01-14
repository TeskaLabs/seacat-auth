import bspump.web
import aiohttp.web
import asab.web
import asab


class MyApplication(bspump.BSPumpApplication):

	def __init__(self):
		super().__init__()

		# svc = self.get_service("bspump.PumpService")

		self.add_module(asab.web.Module)
		self.websvc = self.get_service("asab.WebService")
		self.websvc.WebApp.router.add_get("/test", lookup_webservice)


def lookup_webservice(request):
	return aiohttp.web.Response(text="OK!")


if __name__ == '__main__':
	app = MyApplication()
	app.run()
