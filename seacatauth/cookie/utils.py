import logging

#

L = logging.getLogger(__name__)

#


def set_cookie(app, response, session, cookie_domain=None, secure=None):
	"""
	Add a Set-Cookie header to the response.
	The cookie serves as an identifier of a Seacat Auth session and is used for authentication.
	"""
	cookie_svc = app.get_service("seacatauth.CookieService")

	cookie_name = cookie_svc.get_cookie_name(session.OAuth2.ClientId)
	cookie_domain = cookie_domain or cookie_svc.RootCookieDomain
	if secure is None:
		secure = cookie_svc.CookieSecure

	response.set_cookie(
		cookie_name,
		session.Cookie.Id,
		httponly=True,  # Not accessible from Javascript
		domain=cookie_domain,
		secure=secure,
	)


def delete_cookie(app, response):
	cookie_svc = app.get_service("seacatauth.CookieService")
	response.del_cookie(cookie_svc.CookieName)
