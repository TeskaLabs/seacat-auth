import secrets

from ..session.adapter import SessionAdapter


def oauth2_session_builder(oauth2_data):
	# Token length must be a multiple of AES block size (= 16 bytes)
	token_length = 16 + 32  # The first part is AES CBC init vector, the second is the actual token

	# Session scope defaults to "openid"
	scope = " ".join(oauth2_data.get("scope", ["openid"]))
	yield (SessionAdapter.FNOAuth2Scope, scope)
	yield (SessionAdapter.FNOAuth2AccessToken, secrets.token_bytes(token_length))
	yield (SessionAdapter.FNOAuth2RefreshToken, secrets.token_bytes(token_length))
	yield (SessionAdapter.FNOAuth2IdToken, secrets.token_bytes(token_length))  # TODO: Not sure about this one ...
