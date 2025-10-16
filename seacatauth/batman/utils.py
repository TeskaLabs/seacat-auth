import urllib.parse
import re
import asab
import asab.tls


def split_on_whitespace(s: str) -> list:
	"""
	Split a string by whitespace and return a list of non-empty items

	Args:
		s: Input string

	Returns:
		A list of non-empty items
	"""
	return [item.strip() for item in re.split(r"\s+", s) if len(item) > 0]


def get_url_list(urls: str) -> list[str]:
	"""
	Parse a whitespace-separated list of URLs, each of which may contain multiple
	hostnames separated by semicolons, and return a list of individual server URLs.
	For example, the input string "http://es1;es2:9200 https://es3" will return
	the list ["http://es1/", "http://es2:9200/", "https://es3/"].

	Args:
		urls: A whitespace-separated list of URLs, each of which may contain multiple
			hostnames separated by semicolons.

	Returns:
		A list of individual server URLs.
	"""
	server_urls = []
	if len(urls) > 0:
		urls = split_on_whitespace(urls)
		for url in urls:
			scheme, netloc, path = parse_url(url)
			server_urls.extend(
				urllib.parse.urlunparse((scheme, netloc, path, "", "", ""))
				for netloc in netloc.split(";")
			)

	return server_urls


def parse_url(url: str) -> tuple[str, str, str]:
	"""
	Parse a URL and ensure it has a trailing slash in the path.

	Args:
		url: The URL to parse.

	Returns:
		A tuple (scheme, netloc, path) where path always ends with a slash.
	"""
	parsed_url = urllib.parse.urlparse(url)
	url_path = parsed_url.path
	if not url_path.endswith("/"):
		url_path += "/"

	return parsed_url.scheme, parsed_url.netloc, url_path


def section_has_ssl_option(config_section_name: str):
	"""
	Checks if at least one of SSL config options (cert, key, cafile, capath, cadata etc.) appears in a config section

	Args:
		config_section_name: Name of the config section to check
	"""
	if config_section_name not in asab.Config:
		return False
	for item in asab.Config.options(config_section_name):
		if item in asab.tls.SSLContextBuilder.ConfigDefaults:
			return True
	return False
