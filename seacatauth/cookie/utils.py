import datetime
import logging

#

L = logging.getLogger(__name__)

#


def set_cookie(app, response, session, cookie_domain=None, secure=None):
	"""
	Add a Set-Cookie header to the response.
	The cookie serves as an identifier of a Seacat Auth session and is used for authentication.

	:param app:
		Seacat Auth application
	:param response:
		Response to set cookie to
	:param session:
		Seacat Auth session to get cookie value from
	"""
	cookie_svc = app.get_service("seacatauth.CookieService")
	if cookie_domain in (None, ""):
		cookie_domain = cookie_svc.RootCookieDomain
	if secure is None:
		secure = cookie_svc.CookieSecure

	# Set cookie max age equal to session max age
	# TODO: Set cookie expiration to current session expiration and extend it dynamically
	max_age = int((
		session.Session.MaxExpiration
		- datetime.datetime.now(datetime.timezone.utc)
	).total_seconds())

	response.set_cookie(
		cookie_svc.CookieName,
		session.Cookie.Id,
		httponly=True,  # Not accessible from Javascript
		domain=cookie_domain,
		max_age=max_age,
		secure=secure,
	)


def delete_cookie(app, response):
	cookie_svc = app.get_service("seacatauth.CookieService")
	response.del_cookie(cookie_svc.CookieName)
