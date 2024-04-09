import secrets

from ..session.adapter import SessionAdapter


def oauth2_session_builder(client_id: str, scope: frozenset | None, nonce: str = None, redirect_uri: str = None):
	yield (SessionAdapter.FN.OAuth2.Scope, scope)
	yield (SessionAdapter.FN.OAuth2.ClientId, client_id)
	if redirect_uri is not None:
		yield (SessionAdapter.FN.OAuth2.RedirectUri, redirect_uri)
	if nonce is not None:
		yield (SessionAdapter.FN.OAuth2.Nonce, nonce)
