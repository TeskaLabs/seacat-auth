import secrets

from ..session.adapter import SessionAdapter


def oauth2_session_builder(oauth2_data):
	# Token length must be a multiple of AES block size (= 16 bytes)
	token_length = 16 + 32  # The first part is AES CBC init vector, the second is the actual token

	# TODO: Scope should be always present
	scope = oauth2_data.get("scope")
	if scope is not None:
		scope = list(scope)

	yield (SessionAdapter.FNOAuth2Scope, scope)
	yield (SessionAdapter.FNOAuth2ClientId, oauth2_data["client_id"])
	yield (SessionAdapter.FNOAuth2AccessToken, secrets.token_bytes(token_length))
	yield (SessionAdapter.FNOAuth2RefreshToken, secrets.token_bytes(token_length))
	yield (SessionAdapter.FNOAuth2IdToken, secrets.token_bytes(token_length))
