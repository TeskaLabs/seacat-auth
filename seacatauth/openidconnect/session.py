import secrets

from ..session.adapter import SessionAdapter


def oauth2_session_builder(oauth2_data):
	# Token length must be a multiple of AES block size (= 16 bytes)
	token_length = 16 + 32  # The first part is AES CBC init vector, the second is the actual token

	# TODO: Scope should be always present
	scope = oauth2_data.get("scope")
	if scope is not None:
		scope = list(scope)

	yield (SessionAdapter.FN.OAuth2.Scope, scope)
	yield (SessionAdapter.FN.OAuth2.ClientId, oauth2_data["client_id"])

	if scope is None or "cookie" not in scope:
		yield (SessionAdapter.FN.OAuth2.AccessToken, secrets.token_bytes(token_length))
		yield (SessionAdapter.FN.OAuth2.RefreshToken, secrets.token_bytes(token_length))
