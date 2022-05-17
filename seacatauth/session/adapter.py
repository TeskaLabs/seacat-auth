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
	id: str
	created_at: datetime.datetime
	modified_at: datetime.datetime
	version: int
	parent_id: typing.Optional[str]
	type: typing.Optional[str]
	expiration: datetime.datetime
	max_expiration: datetime.datetime
	expiration_extension: int


@dataclasses.dataclass
class CredentialsData:
	id: str
	created_at: typing.Optional[datetime.datetime]
	modified_at: typing.Optional[datetime.datetime]
	username: typing.Optional[str]
	email: typing.Optional[str]
	phone: typing.Optional[str]


@dataclasses.dataclass
class AuthenticationData:
	totp_set: str
	external_login_options: typing.Optional[list]
	login_descriptor: typing.Optional[dict]
	available_factors: typing.Optional[list]
	last_login: typing.Optional[dict]


@dataclasses.dataclass
class AuthorizationData:
	authz: dict
	roles: list
	resources: list
	tenants: list


@dataclasses.dataclass
class OAuth2Data:
	access_token: typing.Optional[str]
	refresh_token: typing.Optional[str]
	id_token: typing.Optional[str]
	client_id: typing.Optional[str]
	scope: typing.Optional[str]


@dataclasses.dataclass
class CookieData:
	id: typing.Optional[str]


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
		self.Id = self.Session.id
		self.SessionId = self.Session.id
		self.Version = self.Session.version
		self.CreatedAt = self.Session.created_at
		self.ModifiedAt = self.Session.modified_at

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
			self.Session.id,
			self.Session.type,
			self.Session.created_at,
			self.Session.modified_at,
			self.Session.expiration,
			self.Credentials.id,
			" cookie" if self.Cookie is not None else "",
			" oauth2" if self.OAuth2 is not None else "",
		))

	def serialize(self):
		session_dict = {
			self.FN.SessionId: self.Session.id,
			self.FN.CreatedAt: self.Session.created_at,
			self.FN.ModifiedAt: self.Session.modified_at,
			self.FN.Version: self.Session.version,
			self.FN.Session.Type: self.Session.type,
			self.FN.Session.ParentSessionId: self.Session.parent_id,
			self.FN.Session.Expiration: self.Session.expiration,
			self.FN.Session.MaxExpiration: self.Session.max_expiration,
			self.FN.Session.ExpirationExtension: self.Session.expiration_extension,
		}

		if self.Credentials is not None:
			session_dict.update({
				self.FN.Credentials.Id: self.Credentials.id,
				self.FN.Credentials.Email: self.Credentials.email,
				self.FN.Credentials.Phone: self.Credentials.phone,
				self.FN.Credentials.Username: self.Credentials.username,
				self.FN.Credentials.CreatedAt: self.Credentials.created_at,
				self.FN.Credentials.ModifiedAt: self.Credentials.modified_at,
			})

		if self.Authentication is not None:
			session_dict.update({
				self.FN.Authentication.LastLogin: self.Authentication.last_login,
				self.FN.Authentication.LoginDescriptor: self.Authentication.login_descriptor,
				self.FN.Authentication.AvailableFactors: self.Authentication.available_factors,
				self.FN.Authentication.TOTPSet: self.Authentication.totp_set,
			})

		if self.Authorization is not None:
			session_dict.update({
				self.FN.Authorization.Authz: self.Authorization.authz,
				self.FN.Authorization.Tenants: self.Authorization.tenants,
				self.FN.Authorization.Roles: self.Authorization.roles,
				self.FN.Authorization.Resources: self.Authorization.resources,
			})

		if self.Cookie is not None:
			session_dict.update({
				self.FN.Cookie.Id: self.Cookie.id,
			})

		if self.OAuth2 is not None:
			session_dict.update({
				self.FN.OAuth2.IdToken: self.OAuth2.id_token,
				self.FN.OAuth2.AccessToken: self.OAuth2.access_token,
				self.FN.OAuth2.RefreshToken: self.OAuth2.refresh_token,
				self.FN.OAuth2.ClientId: self.OAuth2.client_id,
				self.FN.OAuth2.Scope: self.OAuth2.scope,
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
			id=session_dict.pop(self.FN.SessionId),
			version=session_dict.pop(self.FN.Version),
			created_at=session_dict.pop(self.FN.CreatedAt),
			modified_at=session_dict.pop(self.FN.ModifiedAt),
			type=session_dict.pop(self.FN.Session.Type, None),
			parent_id=session_dict.pop(self.FN.Session.ParentSessionId, None),
			expiration=session_dict.pop(self.FN.Session.Expiration, None),
			max_expiration=session_dict.pop(self.FN.Session.MaxExpiration, None),
			expiration_extension=session_dict.pop(self.FN.Session.ExpirationExtension, None),
		)

	def _deserialize_credentials_data(self, session_dict):
		credentials_id = session_dict.pop(self.FN.Credentials.Id)
		if credentials_id is None:
			return
		return CredentialsData(
			id=credentials_id,
			created_at=session_dict.pop(self.FN.Credentials.CreatedAt, None),
			modified_at=session_dict.pop(self.FN.Credentials.ModifiedAt, None),
			username=session_dict.pop(self.FN.Credentials.Username, None),
			email=session_dict.pop(self.FN.Credentials.Email, None),
			phone=session_dict.pop(self.FN.Credentials.Phone, None),
		)

	def _deserialize_authentication_data(self, session_dict):
		return AuthenticationData(
			totp_set=session_dict.pop(self.FN.Authentication.TOTPSet, None)
				or session_dict.pop("TS", None),
			external_login_options=session_dict.pop(self.FN.Authentication.ExternalLoginOptions, None),
			login_descriptor=session_dict.pop(self.FN.Authentication.LoginDescriptor, None)
				or session_dict.pop("LD", None),
			available_factors=session_dict.pop(self.FN.Authentication.AvailableFactors, None)
				or session_dict.pop("AF", None),
			last_login=session_dict.pop(self.FN.Authentication.LastLogin, None),
		)

	def _deserialize_authorization_data(self, session_dict):
		authz = session_dict.pop(self.FN.Authorization.Authz, None) or session_dict.pop("Authz", None)
		if authz is None:
			return None
		return AuthorizationData(
			authz=authz,
			roles=session_dict.pop(self.FN.Authorization.Roles, None) or session_dict.pop("Rl", None),
			resources=session_dict.pop(self.FN.Authorization.Resources, None) or session_dict.pop("Rs", None),
			tenants=session_dict.pop(self.FN.Authorization.Tenants, None) or session_dict.pop("Tn", None),
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
			id_token=id_token,
			access_token=access_token,
			refresh_token=refresh_token,
			scope=session_dict.pop(SessionAdapter.FN.OAuth2.Scope, None) or oa2_data.pop("S", None),
			client_id=session_dict.pop(SessionAdapter.FN.OAuth2.ClientId, None),
		)

	def _deserialize_cookie_data(self, session_dict):
		sci = session_dict.pop(self.FN.Cookie.Id, None) or session_dict.pop("SCI", None)
		if sci is None:
			return None
		return CookieData(
			id=base64.urlsafe_b64encode(sci).decode("ascii")
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

	# TODO: Backward compatibility. Remove once WebUI adapts to the "_fields" above.
	# >>>
	data.update({
		'id': session_dict.get(SessionAdapter.FN.SessionId),
		'created_at': session_dict.get(SessionAdapter.FN.CreatedAt),
		'modified_at': session_dict.get(SessionAdapter.FN.ModifiedAt),
		'version': session_dict.get(SessionAdapter.FN.Version),
		'Cid': session_dict.get(SessionAdapter.FN.Credentials.Id),
		'exp': session_dict.get(SessionAdapter.FN.Session.Expiration),
	})
	# <<<

	return data
