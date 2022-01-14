import logging

import asab

#

L = logging.getLogger(__name__)

#

asab.Config.add_defaults(
	{
		'bouncer': {
			'allowed_urls': '',  # Allowed URL for the bouncer
			'seacat_auth_url_prefix': '',  # Prefix for SeaCat Auth URLS such as /api etc.
		}
	}
)


class BouncerService(asab.Service):

	def __init__(self, app, service_name='seacatauth.BouncerService'):
		super().__init__(app, service_name)

		self.AllowedUrls = asab.Config['bouncer']['allowed_urls'].split(";")
		self.UrlPrefix = asab.Config['bouncer']['seacat_auth_url_prefix']

	def check_url_allowed(self, url):

		# Check that the URL is allowed
		is_url_allowed = False
		for allowed_url in self.AllowedUrls:
			if len(allowed_url) > 0 and allowed_url in url:
				is_url_allowed = True
				break

		if not is_url_allowed:
			L.warning("URL '{}' is not allowed for bouncing.".format(url))
			return False

		return True
