import secrets

from ..session.adapter import SessionAdapter


def oauth2_session_builder(client_id: str, scope: frozenset | None, nonce: str = None):
	# Token length must be a multiple of AES block size (= 16 bytes)
	token_length = 16 + 32  # The first part is AES CBC init vector, the second is the actual token

	yield (SessionAdapter.FN.OAuth2.Scope, scope)
	yield (SessionAdapter.FN.OAuth2.ClientId, client_id)

	if nonce is not None:
		yield (SessionAdapter.FN.OAuth2.Nonce, nonce)

	if scope is None or "cookie" not in scope:
		yield (SessionAdapter.FN.OAuth2.AccessToken, secrets.token_bytes(token_length))
		yield (SessionAdapter.FN.OAuth2.RefreshToken, secrets.token_bytes(token_length))
