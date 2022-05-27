import dataclasses
import logging
import base64
import datetime
import typing

#

L = logging.getLogger(__name__)

#


@dataclasses.dataclass
class SessionData:
	Id: str
	CreatedAt: datetime.datetime
	ModifiedAt: datetime.datetime
	Version: int
	ParentId: typing.Optional[str]
	Type: typing.Optional[str]
	Expiration: datetime.datetime
	MaxExpiration: datetime.datetime
	ExpirationExtension: int


@dataclasses.dataclass
class CredentialsData:
	Id: str
	CreatedAt: typing.Optional[datetime.datetime]
	ModifiedAt: typing.Optional[datetime.datetime]
	Username: typing.Optional[str]
	Email: typing.Optional[str]
	Phone: typing.Optional[str]


@dataclasses.dataclass
class AuthenticationData:
	TOTPSet: str
	ExternalLoginOptions: typing.Optional[list]
	LoginDescriptor: typing.Optional[dict]
	AvailableFactors: typing.Optional[list]
	LastLogin: typing.Optional[dict]


@dataclasses.dataclass
class AuthorizationData:
	Authz: dict
	Roles: list
	Resources: list
	Tenants: list


@dataclasses.dataclass
class OAuth2Data:
	AccessToken: typing.Optional[str]
	RefreshToken: typing.Optional[str]
	IDToken: typing.Optional[str]
	ClientId: typing.Optional[str]
	Scope: typing.Optional[str]


@dataclasses.dataclass
class CookieData:
	Id: typing.Optional[str]


class SessionAdapter:
	"""
	Light object that represent a momentary view on the persisted session
	"""

	class FN:
		"""
		Database field names
		"""

		SessionId = "_id"
		CreatedAt = "_c"
		ModifiedAt = "_m"
		Version = "_v"

		class Session:
			_prefix = "s"
			Type = "s_t"
			ParentSessionId = "s_pid"
			Expiration = "s_exp"
			MaxExpiration = "s_expm"
			ExpirationExtension = "s_expe"

		class Credentials:
			_prefix = "c"
			Id = "c_id"
			Username = "c_u"
			Email = "c_e"
			Phone = "c_p"
			CreatedAt = "c_c"
			ModifiedAt = "c_m"

		class Authorization:
			_prefix = "az"
			Tenants = "az_t"
			Roles = "az_rl"
			Resources = "az_rs"
			Authz = "az_az"

		class Authentication:
			_prefix = "an"
			TOTPSet = "an_ts"
			ExternalLoginOptions = "an_ex"
			LoginDescriptor = "an_ld"
			AvailableFactors = "an_af"
			LastLogin = "an_ll"

		class OAuth2:
			_prefix = "oa"
			IdToken = "oa_it"
			AccessToken = "oa_at"
			RefreshToken = "oa_rt"
			Scope = "oa_sc"
			ClientId = "oa_cl"

		class Cookie:
			_prefix = "ck"
			Id = "ck_sci"

	# Fields that are stored encrypted
	SensitiveFields = frozenset([
		FN.OAuth2.IdToken,
		FN.OAuth2.AccessToken,
		FN.OAuth2.RefreshToken,
		FN.Cookie.Id,
		"oa.Ti", "oa.Ta", "oa.Tr", "oa.S",  # BACK COMPAT
	])

	EncryptedPrefix = b"$aescbc$"

	def __init__(self, session_svc, session_dict):
		self._decrypt_sensitive_fields(session_dict, session_svc)

		self.Session = self._deserialize_session_data(session_dict)
		self.Id = self.Session.Id
		self.SessionId = self.Session.Id
		self.Version = self.Session.Version
		self.CreatedAt = self.Session.CreatedAt
		self.ModifiedAt = self.Session.ModifiedAt

		self.Credentials = self._deserialize_credentials_data(session_dict)
		self.Authentication = self._deserialize_authentication_data(session_dict)
		self.Authorization = self._deserialize_authorization_data(session_dict)
		self.Cookie = self._deserialize_cookie_data(session_dict)
		self.OAuth2 = self._deserialize_oauth2_data(session_dict)

		if len(session_dict) > 0:
			self.Data = session_dict
		else:
			self.Data = None

	def __repr__(self):
		return ("<{} {} t:{} c:{} m:{} exp:{} cid:{} ({}{})>".format(
			self.__class__.__name__,
			self.Session.Id,
			self.Session.Type,
			self.Session.CreatedAt,
			self.Session.ModifiedAt,
			self.Session.Expiration,
			self.Credentials.Id,
			" cookie" if self.Cookie is not None else "",
			" oauth2" if self.OAuth2 is not None else "",
		))

	def serialize(self):
		session_dict = {
			self.FN.SessionId: self.Session.Id,
			self.FN.CreatedAt: self.Session.CreatedAt,
			self.FN.ModifiedAt: self.Session.ModifiedAt,
			self.FN.Version: self.Session.Version,
			self.FN.Session.Type: self.Session.Type,
			self.FN.Session.ParentSessionId: self.Session.ParentId,
			self.FN.Session.Expiration: self.Session.Expiration,
			self.FN.Session.MaxExpiration: self.Session.MaxExpiration,
			self.FN.Session.ExpirationExtension: self.Session.ExpirationExtension,
		}

		if self.Credentials is not None:
			session_dict.update({
				self.FN.Credentials.Id: self.Credentials.Id,
				self.FN.Credentials.Email: self.Credentials.Email,
				self.FN.Credentials.Phone: self.Credentials.Phone,
				self.FN.Credentials.Username: self.Credentials.Username,
				self.FN.Credentials.CreatedAt: self.Credentials.CreatedAt,
				self.FN.Credentials.ModifiedAt: self.Credentials.ModifiedAt,
			})

		if self.Authentication is not None:
			session_dict.update({
				self.FN.Authentication.LastLogin: self.Authentication.LastLogin,
				self.FN.Authentication.LoginDescriptor: self.Authentication.LoginDescriptor,
				self.FN.Authentication.AvailableFactors: self.Authentication.AvailableFactors,
				self.FN.Authentication.TOTPSet: self.Authentication.TOTPSet,
			})

		if self.Authorization is not None:
			session_dict.update({
				self.FN.Authorization.Authz: self.Authorization.Authz,
				self.FN.Authorization.Tenants: self.Authorization.Tenants,
				self.FN.Authorization.Roles: self.Authorization.Roles,
				self.FN.Authorization.Resources: self.Authorization.Resources,
			})

		if self.Cookie is not None:
			session_dict.update({
				self.FN.Cookie.Id: self.Cookie.Id,
			})

		if self.OAuth2 is not None:
			session_dict.update({
				self.FN.OAuth2.IdToken: self.OAuth2.IDToken,
				self.FN.OAuth2.AccessToken: self.OAuth2.AccessToken,
				self.FN.OAuth2.RefreshToken: self.OAuth2.RefreshToken,
				self.FN.OAuth2.ClientId: self.OAuth2.ClientId,
				self.FN.OAuth2.Scope: self.OAuth2.Scope,
			})

		# TODO: encrypt sensitive fields

		return {k: v for k, v in session_dict.items() if v is not None}

	def rest_get(self):
		session_dict = self.serialize()
		return rest_get(session_dict)

	def _decrypt_sensitive_fields(self, session_dict, session_svc):
		# Decrypt sensitive fields
		for field in self.SensitiveFields:
			# BACK COMPAT: Handle nested dictionaries
			obj = session_dict
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

	def _deserialize_session_data(self, session_dict):
		return SessionData(
			Id=session_dict.pop(self.FN.SessionId),
			Version=session_dict.pop(self.FN.Version),
			CreatedAt=session_dict.pop(self.FN.CreatedAt),
			ModifiedAt=session_dict.pop(self.FN.ModifiedAt),
			Type=session_dict.pop(self.FN.Session.Type, None),
			ParentId=session_dict.pop(self.FN.Session.ParentSessionId, None),
			Expiration=session_dict.pop(self.FN.Session.Expiration, None),
			MaxExpiration=session_dict.pop(self.FN.Session.MaxExpiration, None),
			ExpirationExtension=session_dict.pop(self.FN.Session.ExpirationExtension, None),
		)

	def _deserialize_credentials_data(self, session_dict):
		credentials_id = session_dict.pop(self.FN.Credentials.Id)
		if credentials_id is None:
			return
		return CredentialsData(
			Id=credentials_id,
			CreatedAt=session_dict.pop(self.FN.Credentials.CreatedAt, None),
			ModifiedAt=session_dict.pop(self.FN.Credentials.ModifiedAt, None),
			Username=session_dict.pop(self.FN.Credentials.Username, None),
			Email=session_dict.pop(self.FN.Credentials.Email, None),
			Phone=session_dict.pop(self.FN.Credentials.Phone, None),
		)

	# TODO: The following methods contain BACK-COMPAT fallbacks (the or-sections)
	#   Remove the fallbacks in December 2022

	def _deserialize_authentication_data(self, session_dict):
		return AuthenticationData(
			TOTPSet=session_dict.pop(self.FN.Authentication.TOTPSet, None)
			or session_dict.pop("TS", None),
			ExternalLoginOptions=session_dict.pop(self.FN.Authentication.ExternalLoginOptions, None),
			LoginDescriptor=session_dict.pop(self.FN.Authentication.LoginDescriptor, None)
			or session_dict.pop("LD", None),
			AvailableFactors=session_dict.pop(self.FN.Authentication.AvailableFactors, None)
			or session_dict.pop("AF", None),
			LastLogin=session_dict.pop(self.FN.Authentication.LastLogin, None),
		)

	def _deserialize_authorization_data(self, session_dict):
		authz = session_dict.pop(self.FN.Authorization.Authz, None) or session_dict.pop("Authz", None)
		if authz is None:
			return None
		return AuthorizationData(
			Authz=authz,
			Roles=session_dict.pop(self.FN.Authorization.Roles, None) or session_dict.pop("Rl", None),
			Resources=session_dict.pop(self.FN.Authorization.Resources, None) or session_dict.pop("Rs", None),
			Tenants=session_dict.pop(self.FN.Authorization.Tenants, None) or session_dict.pop("Tn", None),
		)

	def _deserialize_oauth2_data(self, session_dict):
		oa2_data = session_dict.pop("oa", {})  # BACK COMPAT
		id_token = session_dict.pop(self.FN.OAuth2.IdToken, None) or oa2_data.pop("Ti", None)
		if id_token is None:
			return

		id_token = base64.urlsafe_b64encode(id_token).decode("ascii")

		access_token = session_dict.pop(SessionAdapter.FN.OAuth2.AccessToken) or oa2_data.pop("Ta", None)
		if access_token is not None:
			# Base64-encode the tokens for OIDC service convenience
			access_token = base64.urlsafe_b64encode(access_token).decode("ascii")

		refresh_token = session_dict.pop(SessionAdapter.FN.OAuth2.RefreshToken) or oa2_data.pop("Tr", None)
		if refresh_token is not None:
			refresh_token = base64.urlsafe_b64encode(refresh_token).decode("ascii")

		return OAuth2Data(
			IDToken=id_token,
			AccessToken=access_token,
			RefreshToken=refresh_token,
			Scope=session_dict.pop(SessionAdapter.FN.OAuth2.Scope, None) or oa2_data.pop("S", None),
			ClientId=session_dict.pop(SessionAdapter.FN.OAuth2.ClientId, None),
		)

	def _deserialize_cookie_data(self, session_dict):
		sci = session_dict.pop(self.FN.Cookie.Id, None) or session_dict.pop("SCI", None)
		if sci is None:
			return None
		return CookieData(
			Id=base64.urlsafe_b64encode(sci).decode("ascii")
		)


def rest_get(session_dict):
	data = {
		"_id": session_dict.get(SessionAdapter.FN.SessionId),
		"_c": session_dict.get(SessionAdapter.FN.CreatedAt),
		"_m": session_dict.get(SessionAdapter.FN.ModifiedAt),
		"_v": session_dict.get(SessionAdapter.FN.Version),
		"type": session_dict.get(SessionAdapter.FN.Session.Type),
		"expiration": session_dict.get(SessionAdapter.FN.Session.Expiration),
		"max_expiration": session_dict.get(SessionAdapter.FN.Session.MaxExpiration),
		"credentials_id": session_dict.get(SessionAdapter.FN.Credentials.Id),
		"login_descriptor": session_dict.get(SessionAdapter.FN.Authentication.LoginDescriptor),
		"authz": session_dict.get(SessionAdapter.FN.Authorization.Authz),
	}
	if session_dict.get(SessionAdapter.FN.OAuth2.IdToken) is not None:
		data["oauth2"] = True
	if session_dict.get(SessionAdapter.FN.Cookie.Id) is not None:
		data["cookie"] = True

	return data
