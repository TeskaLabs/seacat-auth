import logging
import base64
import datetime

#

L = logging.getLogger(__name__)

#


class SessionAdapter:
	"""
	Light object that represent a momentary view on the persisted session
	"""

	class FN:
		"""
		Database field names
		"""
		SessionType = "t"
		ParentSessionId = "ps"
		Expiration = "exp"
		MaxExpiration = "expm"
		ExpirationExtension = "expe"

		SessionCookieId = "sci"

		class Credentials:
			_FN = "c"
			Id = "c.id"
			Username = "c.u"
			Email = "c.e"
			Phone = "c.p"
			CreatedAt = "c.c"
			ModifiedAt = "c.m"

		class Authorization:
			_FN = "az"
			Tenants = "az.t"
			Roles = "az.rl"
			Resources = "az.rs"
			Authz = "az.az"

		class Authentication:
			_FN = "an"
			TOTPSet = "an.ts"
			ExternalLoginOptions = "an.ex"
			LoginDescriptor = "an.ld"
			AvailableFactors = "an.af"

		class OAuth2:
			_FN = "oa"
			OAuth2IdToken = "oa.it"
			OAuth2AccessToken = "oa.at"
			OAuth2RefreshToken = "oa.rt"
			OAuth2Scope = "oa.sc"
			OAuth2ClientId = "oa.cl"

	# Session properties
	FNSessionType = "t"
	FNParentSessionId = "ps"
	FNExpiration = "exp"
	FNMaxExpiration = "expm"
	FNExpirationExtension = "expe"

	# Credential fields
	FNCredentialsId = "cid"
	FNCredentials = "c"
	FNCredentialsUsername = "c.u"
	FNCredentialsEmail = "c.e"
	FNCredentialsPhone = "c.p"
	FNCredentialsCreatedAt = "c.c"
	FNCredentialsModifiedAt = "c.m"

	# Authorization fields
	FNTenants = "az.t"
	FNRoles = "az.rl"
	FNResources = "az.rs"
	FNAuthz = "az.az"

	# Authentication fields
	FNTOTPSet = "an.ts"
	FNExternalLoginOptions = "an.ext"
	FNLoginDescriptor = "an.ld"
	FNAvailableFactors = "an.af"

	# Cookie fields
	FNSessionCookieId = "sci"

	# OAuth2 fields
	FNOAuth2 = "oa"
	FNOAuth2IdToken = "oa.it"
	FNOAuth2AccessToken = "oa.at"
	FNOAuth2RefreshToken = "oa.rt"
	FNOAuth2Scope = "oa.sc"
	FNOAuth2ClientId = "oa.cl"

	# Fields that are stored encrypted
	SensitiveFields = frozenset([
		FNOAuth2IdToken,
		FNOAuth2AccessToken,
		FNOAuth2RefreshToken,
		FNSessionCookieId,
	])

	EncryptedPrefix = b"$aescbc$"

	def __init__(self, session_svc, session_dict):

		self.SessionId = session_dict.pop('_id')
		self.Version = session_dict.pop('_v')
		self.CreatedAt = session_dict.pop('_c')
		self.ModifiedAt = session_dict.pop('_m')

		self.Type = session_dict.pop(self.FNSessionType)
		self.ParentSessionId = session_dict.pop(self.FNParentSessionId, None)
		self.Expiration = session_dict.pop(self.FNExpiration)
		self.MaxExpiration = session_dict.pop(self.FNMaxExpiration, None)
		self.TouchExtension = session_dict.pop(self.FNExpirationExtension, None)

		self.CredentialsId = structured_pop(session_dict, self.FN.Credentials.Id, None) or session_dict.pop("Cid", None)
		self.CredentialsUsername = structured_pop(session_dict, self.FN.Credentials.Username, None)
		self.CredentialsEmail = structured_pop(session_dict, self.FN.Credentials.Email, None)
		self.CredentialsPhone = structured_pop(session_dict, self.FN.Credentials.Phone, None)
		self.CredentialsCreatedAt = structured_pop(session_dict, self.FN.Credentials.CreatedAt, None)
		self.CredentialsModifiedAt = structured_pop(session_dict, self.FN.Credentials.ModifiedAt, None)

		self.Authz = session_dict.pop(self.FNAuthz, None) or session_dict.pop("Authz", None)
		self.Roles = session_dict.pop(self.FNRoles, None) or session_dict.pop("Rl", None)
		self.Resources = session_dict.pop(self.FNResources, None) or session_dict.pop("Rs", None)
		self.Tenants = session_dict.pop(self.FNTenants, None) or session_dict.pop("Tn", None)

		self.LoginDescriptor = session_dict.pop(self.FNLoginDescriptor, None) or session_dict.pop("LD", None)
		self.AvailableFactors = session_dict.pop(self.FNAvailableFactors, None) or session_dict.pop("AF", None)
		self.AuthnTOTPSet = session_dict.pop(self.FNTOTPSet, None) or session_dict.pop("TS", None)
		self.ExternalLoginOptions = session_dict.pop(self.FNExternalLoginOptions, None)

		data = session_dict.copy()

		# Decrypt sensitive fields
		for field in self.SensitiveFields:
			# Handle nested dictionaries
			obj = data
			keys = field.split(".")
			for key in keys[:-1]:
				if key not in obj:
					break
				obj = obj[key]
			else:
				# BACK COMPAT: Keep values without prefix raw
				# TODO: Remove support once proper m2m tokens are in place
				value = obj[keys[-1]]
				if value.startswith(self.EncryptedPrefix):
					obj[keys[-1]] = session_svc.aes_decrypt(value[len(self.EncryptedPrefix):])

		sci = data.pop(self.FNSessionCookieId, None)
		if sci is not None:
			self.SessionCookieId = base64.urlsafe_b64encode(sci).decode("ascii")

		# OAuth2 / OpenId Connect
		oa2_data = data.pop(self.FNOAuth2, None)
		if oa2_data is not None:
			self.OAuth2 = {}
			# Base64-encode the tokens for OIDC service convenience
			v = oa2_data.pop(self.FNOAuth2AccessToken) or oa2_data.pop("Ta")
			if v is not None:
				self.OAuth2["access_token"] = base64.urlsafe_b64encode(v).decode("ascii")
			v = oa2_data.pop(self.FNOAuth2IdToken) or oa2_data.pop("Ti")
			if v is not None:
				self.OAuth2["id_token"] = base64.urlsafe_b64encode(v).decode("ascii")
			v = oa2_data.pop(self.FNOAuth2RefreshToken) or oa2_data.pop("Tr")
			if v is not None:
				self.OAuth2["refresh_token"] = base64.urlsafe_b64encode(v).decode("ascii")
			v = oa2_data.pop(self.FNOAuth2Scope) or oa2_data.pop("S")
			if v is not None:
				self.OAuth2["scope"] = v
			v = oa2_data.pop(self.FNOAuth2ClientId)
			if v is not None:
				self.OAuth2["client_id"] = v

		else:
			self.OAuth2 = None

		if len(data) > 0:
			self.Data = data
		else:
			self.Data = None


	def get_rest(self):
		d = {
			"_id": self.SessionId,
			"_v": self.Version,
			"_c": "{}Z".format(self.CreatedAt.isoformat()),
			"_m": "{}Z".format(self.ModifiedAt.isoformat()),
			"expiration": "{}Z".format(self.Expiration.isoformat()),
			"login_descriptor": self.LoginDescriptor,
			"type": self.Type,
		}

		# TODO: Backward compatibility. Remove once WebUI adapts to the "_fields" above.
		# >>>
		d.update({
			'id': self.SessionId,
			'version': self.Version,
			'created_at': "{}Z".format(self.CreatedAt.isoformat()),
			'modified_at': "{}Z".format(self.ModifiedAt.isoformat())
		})
		# <<<

		if self.MaxExpiration is not None:
			d['max_expiration'] = "{}Z".format(self.MaxExpiration.isoformat())
		if self.TouchExtension is not None:
			d['touch_extension'] = str(datetime.timedelta(seconds=self.TouchExtension))
		if self.CredentialsId is not None:
			d['credentials_id'] = self.CredentialsId
		if self.Authz is not None:
			d['authz'] = self.Authz
		if self.Data is not None:
			d['data'] = self.Data
		if self.OAuth2 is not None:
			d['oauth2'] = self.OAuth2
		return d


	def __repr__(self):
		return("<{} sid:{} t:{} c:{} m:{} exp:{} cred:{} authz:{} ld:{} sci:{} {} {}>".format(
			self.__class__.__name__,
			self.SessionId,
			self.Type,
			self.CreatedAt,
			self.ModifiedAt,
			self.Expiration,
			"yes" if self.CredentialsId is not None else "NA",
			"yes" if self.Authz is not None else "NA",
			self.LoginDescriptor,
			self.SessionCookieId,
			self.Data,
			self.OAuth2,
		))


def structured_pop(data, fields, fallback=None):
	if isinstance(fields, str):
		field, *fields = fields.split(".")
	else:
		field, *fields = fields

	if len(fields) == 0:
		return data.pop(field, fallback)
	else:
		try:
			subdata = data[field]
			if not isinstance(subdata, dict):
				return fallback
			item = structured_pop(subdata, fields, fallback)
			if len(subdata) == 0:
				del data[field]
			return item
		except KeyError:
			return fallback
