import dataclasses
import logging
import base64
import datetime

#
import typing

L = logging.getLogger(__name__)

#


@dataclasses.dataclass
class OAuth2:
	access_token: typing.Optional[str]
	refresh_token: typing.Optional[str]
	id_token: typing.Optional[str]
	client_id: typing.Optional[str]
	scope: typing.Optional[str]

	def __bool__(self):
		return self.access_token or self.id_token

	@classmethod
	def build(cls, session_dict):
		oa2_data = session_dict.pop("oa", {})  # BACK COMPAT
		access_token = session_dict.pop(SessionAdapter.FN.OAuth2.AccessToken) or oa2_data.pop("Ta", None),
		if access_token is not None:
			# Base64-encode the tokens for OIDC service convenience
			access_token = base64.urlsafe_b64encode(access_token).decode("ascii")

		refresh_token = session_dict.pop(SessionAdapter.FN.OAuth2.RefreshToken) or oa2_data.pop("Tr", None),
		if refresh_token is not None:
			refresh_token = base64.urlsafe_b64encode(refresh_token).decode("ascii")

		id_token = session_dict.pop(SessionAdapter.FN.OAuth2.IdToken) or oa2_data.pop("Ti", None),
		if id_token is not None:
			id_token = base64.urlsafe_b64encode(id_token).decode("ascii")

		scope = session_dict.pop(SessionAdapter.FN.OAuth2.Scope, None) or oa2_data.pop("S", None),
		client_id = session_dict.pop(SessionAdapter.FN.OAuth2.ClientId, None),

		return cls(
			access_token,
			refresh_token,
			id_token,
			scope,
			client_id,
		)


class SessionAdapter:
	"""
	Light object that represent a momentary view on the persisted session
	"""

	class FN:
		"""
		Database field names
		"""
		class Session:
			_FN = "s"
			Type = "s_t"
			ParentSessionId = "s_ps"
			Expiration = "s_exp"
			MaxExpiration = "s_expm"
			ExpirationExtension = "s_expe"

		class Credentials:
			_FN = "c"
			Id = "c_id"
			Username = "c_u"
			Email = "c_e"
			Phone = "c_p"
			CreatedAt = "c_c"
			ModifiedAt = "c_m"

		class Authorization:
			_FN = "az"
			Tenants = "az_t"
			Roles = "az_rl"
			Resources = "az_rs"
			Authz = "az_az"

		class Authentication:
			_FN = "an"
			TOTPSet = "an_ts"
			ExternalLoginOptions = "an_ex"
			LoginDescriptor = "an_ld"
			AvailableFactors = "an_af"

		class OAuth2:
			_FN = "oa"
			IdToken = "oa_it"
			AccessToken = "oa_at"
			RefreshToken = "oa_rt"
			Scope = "oa_sc"
			ClientId = "oa_cl"

		class Cookie:
			_FN = "ck"
			SessionCookieId = "ck_sci"


	# Fields that are stored encrypted
	SensitiveFields = frozenset([
		FN.OAuth2.IdToken,
		FN.OAuth2.AccessToken,
		FN.OAuth2.RefreshToken,
		FN.Cookie.SessionCookieId,
		"oa.Ti", "oa.Ta",  "oa.Tr",  "oa.S",  # BACK COMPAT
	])

	EncryptedPrefix = b"$aescbc$"

	def __init__(self, session_svc, session_dict):

		self.SessionId = session_dict.pop('_id')
		self.Version = session_dict.pop('_v')
		self.CreatedAt = session_dict.pop('_c')
		self.ModifiedAt = session_dict.pop('_m')

		self.Type = session_dict.pop(self.FN.Session.Type, None)
		self.ParentSessionId = session_dict.pop(self.FN.Session.ParentSessionId, None)
		self.Expiration = session_dict.pop(self.FN.Session.Expiration)
		self.MaxExpiration = session_dict.pop(self.FN.Session.MaxExpiration, None)
		self.TouchExtension = session_dict.pop(self.FN.Session.ExpirationExtension, None)

		self.CredentialsId = session_dict.pop(self.FN.Credentials.Id, None) or session_dict.pop("Cid", None)
		self.CredentialsUsername = session_dict.pop(self.FN.Credentials.Username, None)
		self.CredentialsEmail = session_dict.pop(self.FN.Credentials.Email, None)
		self.CredentialsPhone = session_dict.pop(self.FN.Credentials.Phone, None)
		self.CredentialsCreatedAt = session_dict.pop(self.FN.Credentials.CreatedAt, None)
		self.CredentialsModifiedAt = session_dict.pop(self.FN.Credentials.ModifiedAt, None)

		self.Authz = session_dict.pop(self.FN.Authorization.Authz, None) or session_dict.pop("Authz", None)
		self.Roles = session_dict.pop(self.FN.Authorization.Roles, None) or session_dict.pop("Rl", None)
		self.Resources = session_dict.pop(self.FN.Authorization.Resources, None) or session_dict.pop("Rs", None)
		self.Tenants = session_dict.pop(self.FN.Authorization.Tenants, None) or session_dict.pop("Tn", None)

		self.LoginDescriptor = session_dict.pop(self.FN.Authentication.LoginDescriptor, None) or session_dict.pop("LD", None)
		self.AvailableFactors = session_dict.pop(self.FN.Authentication.AvailableFactors, None) or session_dict.pop("AF", None)
		self.AuthnTOTPSet = session_dict.pop(self.FN.Authentication.TOTPSet, None) or session_dict.pop("TS", None)
		self.ExternalLoginOptions = session_dict.pop(self.FN.Authentication.ExternalLoginOptions, None)

		data = session_dict.copy()

		# Decrypt sensitive fields
		for field in self.SensitiveFields:
			# BACK COMPAT: Handle nested dictionaries
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

		sci = data.pop(self.FN.Cookie.SessionCookieId, None) or session_dict.pop("SCI", None)
		if sci is not None:
			self.SessionCookieId = base64.urlsafe_b64encode(sci).decode("ascii")

		# OAuth2 / OpenId Connect
		self.OAuth2 = OAuth2.build(data)

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
