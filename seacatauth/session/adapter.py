import dataclasses
import logging
import base64
import datetime
import typing

from ..authz.rbac.service import RBACService

#

L = logging.getLogger(__name__)

#


@dataclasses.dataclass
class SessionData:
	Id: str
	CreatedAt: datetime.datetime
	ModifiedAt: datetime.datetime
	Version: int
	ParentSessionId: typing.Optional[str]
	Type: typing.Optional[str]
	Expiration: datetime.datetime
	MaxExpiration: datetime.datetime
	ExpirationExtension: int
	TrackId: typing.Optional[bytes]


@dataclasses.dataclass
class CredentialsData:
	Id: str
	CreatedAt: typing.Optional[datetime.datetime]
	ModifiedAt: typing.Optional[datetime.datetime]
	Username: typing.Optional[str]
	Email: typing.Optional[str]
	Phone: typing.Optional[str]
	CustomData: typing.Optional[dict]


@dataclasses.dataclass
class AuthenticationData:
	AuthnTime: datetime.datetime
	TOTPSet: str
	ExternalLoginOptions: typing.Optional[list]
	LoginDescriptor: typing.Optional[str]
	LoginFactors: typing.Optional[list]
	AvailableFactors: typing.Optional[list]
	LastLogin: typing.Optional[dict]
	IsAnonymous: typing.Optional[bool]
	ImpersonatorCredentialsId: typing.Optional[str]
	ImpersonatorSessionId: typing.Optional[str]


@dataclasses.dataclass
class AuthorizationData:
	Authz: dict
	AssignedTenants: list


@dataclasses.dataclass
class OAuth2Data:
	AccessToken: typing.Optional[str]
	RefreshToken: typing.Optional[str]
	IDToken: typing.Optional[str]
	ClientId: typing.Optional[str]
	Scope: typing.Optional[str]
	Nonce: typing.Optional[str]
	RedirectUri: typing.Optional[str]


@dataclasses.dataclass
class CookieData:
	Id: typing.Optional[str]
	Domain: typing.Optional[str]


@dataclasses.dataclass
class BatmanData:
	Token: typing.Optional[str]


class SessionAdapter:
	"""
	Light object that represent a momentary view on the persisted session
	"""

	ALGORITHMIC_SESSION_ID = "<algorithmic>"

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
			TrackId = "s_tid"
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
			CustomData = "c_d"

		class Authorization:
			_prefix = "az"
			AssignedTenants = "az_t"
			Authz = "az_az"

		class Authentication:
			_prefix = "an"
			AuthnTime = "an_t"
			TOTPSet = "an_ts"
			ExternalLoginOptions = "an_ex"
			LoginDescriptor = "an_ld"
			LoginFactors = "an_lf"
			AvailableFactors = "an_af"
			LastLogin = "an_ll"
			IsAnonymous = "an_ano"
			ImpersonatorCredentialsId = "an_imcid"
			ImpersonatorSessionId = "an_imsid"

		class OAuth2:
			_prefix = "oa"
			IdToken = "oa_it"
			AccessToken = "oa_at"
			RefreshToken = "oa_rt"
			Scope = "oa_sc"
			ClientId = "oa_cl"
			Nonce = "oa_no"
			RedirectUri = "oa_ru"

		class Cookie:
			_prefix = "ck"
			Id = "ck_sci"
			Domain = "ck_d"

		class Batman:
			_prefix = "ba"
			Token = "ba_t"

	# Session identifiers are stored encrypted
	# They are used as session lookup keys and need special encryption treatment for that
	EncryptedIdentifierFields = frozenset([
		FN.OAuth2.AccessToken,
		FN.OAuth2.RefreshToken,
		FN.Cookie.Id,
	])

	# Other sensitive fields (not used as lookup keys)
	# They use regular encryption provided by asab.storage
	EncryptedAttributes = frozenset([
		FN.Batman.Token,
		FN.OAuth2.IdToken,
	])

	EncryptedPrefix = b"$aescbc$"

	def __init__(self, session_svc, session_dict):
		self._decrypt_encrypted_identifiers(session_dict, session_svc)

		self.Session = self._deserialize_session_data(session_dict)
		self.Id = self.Session.Id
		self.SessionId = self.Session.Id
		self.Version = self.Session.Version
		self.CreatedAt = self.Session.CreatedAt
		self.ModifiedAt = self.Session.ModifiedAt
		self.TrackId = self.Session.TrackId

		self.Credentials = self._deserialize_credentials_data(session_dict)
		self.Authentication = self._deserialize_authentication_data(session_dict)
		self.Authorization = self._deserialize_authorization_data(session_dict)
		self.Cookie = self._deserialize_cookie_data(session_dict)
		self.OAuth2 = self._deserialize_oauth2_data(session_dict)
		self.Batman = self._deserialize_batman_data(session_dict)

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
			self.FN.Session.ParentSessionId: self.Session.ParentSessionId,
			self.FN.Session.Expiration: self.Session.Expiration,
			self.FN.Session.MaxExpiration: self.Session.MaxExpiration,
			self.FN.Session.ExpirationExtension: self.Session.ExpirationExtension,
			self.FN.Session.TrackId: self.Session.TrackId,
		}

		if self.Credentials is not None:
			session_dict.update({
				self.FN.Credentials.Id: self.Credentials.Id,
				self.FN.Credentials.Email: self.Credentials.Email,
				self.FN.Credentials.Phone: self.Credentials.Phone,
				self.FN.Credentials.Username: self.Credentials.Username,
				self.FN.Credentials.CustomData: self.Credentials.CustomData,
				self.FN.Credentials.CreatedAt: self.Credentials.CreatedAt,
				self.FN.Credentials.ModifiedAt: self.Credentials.ModifiedAt,
			})

		if self.Authentication is not None:
			session_dict.update({
				self.FN.Authentication.AuthnTime: self.Authentication.AuthnTime,
				self.FN.Authentication.LastLogin: self.Authentication.LastLogin,
				self.FN.Authentication.LoginDescriptor: self.Authentication.LoginDescriptor,
				self.FN.Authentication.LoginFactors: self.Authentication.LoginFactors,
				self.FN.Authentication.AvailableFactors: self.Authentication.AvailableFactors,
				self.FN.Authentication.TOTPSet: self.Authentication.TOTPSet,
				self.FN.Authentication.IsAnonymous: self.Authentication.IsAnonymous,
				self.FN.Authentication.ImpersonatorCredentialsId: self.Authentication.ImpersonatorCredentialsId,
				self.FN.Authentication.ImpersonatorSessionId: self.Authentication.ImpersonatorSessionId,
			})

		if self.Authorization is not None:
			session_dict.update({
				self.FN.Authorization.Authz: self.Authorization.Authz,
				self.FN.Authorization.AssignedTenants: self.Authorization.AssignedTenants,
			})

		if self.Cookie is not None:
			session_dict.update({
				self.FN.Cookie.Id: self.Cookie.Id,
				self.FN.Cookie.Domain: self.Cookie.Domain,
			})

		if self.OAuth2 is not None:
			session_dict.update({
				self.FN.OAuth2.IdToken: self.OAuth2.IDToken,
				self.FN.OAuth2.AccessToken: self.OAuth2.AccessToken,
				self.FN.OAuth2.RefreshToken: self.OAuth2.RefreshToken,
				self.FN.OAuth2.ClientId: self.OAuth2.ClientId,
				self.FN.OAuth2.Scope: self.OAuth2.Scope,
				self.FN.OAuth2.Nonce: self.OAuth2.Nonce,
				self.FN.OAuth2.RedirectUri: self.OAuth2.RedirectUri,
			})

		if self.Batman is not None:
			session_dict.update({
				self.FN.Batman.Token: self.Batman.Token,
			})

		return {k: v for k, v in session_dict.items() if v is not None}

	def rest_get(self):
		session_dict = self.serialize()
		return rest_get(session_dict)

	def is_algorithmic(self) -> bool:
		"""
		Is the session algorithmic (i.e. not stored in the database)?
		"""
		return self.SessionId == self.ALGORITHMIC_SESSION_ID

	def is_anonymous(self) -> bool:
		"""
		Is this session anonymous (guest session, without authentication)?
		"""
		return self.Authentication is not None and bool(self.Authentication.IsAnonymous)

	def is_superuser(self) -> bool:
		"""
		Does this session have superuser authorization?
		"""
		return (
			self.Authorization is not None
			and self.Authorization.Authz is not None
			and RBACService.is_superuser(self.Authorization.Authz)
		)

	def has_tenant_access(self, tenant_id: str) -> bool:
		"""
		Is this session authorized to access the tenant?
		"""
		assert tenant_id != "*"
		return self.is_superuser() or (
			self.Authorization is not None
			and self.Authorization.Authz is not None
			and tenant_id in self.Authorization.Authz
		)

	def has_resource_access(self, tenant_id: str, resource_id: str) -> bool:
		"""
		Is this session authorized to access the resource under the tenant?
		"""
		assert tenant_id != "*"
		return (
			self.Authorization is not None
			and self.Authorization.Authz is not None
			and RBACService.has_resource_access(self.Authorization.Authz, tenant_id, {resource_id})
		)

	def has_global_resource_access(self, resource_id: str) -> bool:
		"""
		Is this session authorized to access the resource globally?
		"""
		return (
			self.Authorization is not None
			and self.Authorization.Authz is not None
			and RBACService.has_resource_access(self.Authorization.Authz, None, {resource_id})
		)

	def _decrypt_encrypted_identifiers(self, session_dict, session_svc):
		# Decrypt sensitive fields
		for field in self.EncryptedIdentifierFields:
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
				value = obj.get(keys[-1])
				if value is not None and value.startswith(self.EncryptedPrefix):
					obj[keys[-1]] = session_svc.aes_decrypt(value[len(self.EncryptedPrefix):])

	@classmethod
	def _deserialize_session_data(cls, session_dict):
		return SessionData(
			Id=session_dict.pop(cls.FN.SessionId),
			Version=session_dict.pop(cls.FN.Version),
			CreatedAt=session_dict.pop(cls.FN.CreatedAt),
			ModifiedAt=session_dict.pop(cls.FN.ModifiedAt),
			Type=session_dict.pop(cls.FN.Session.Type, None),
			ParentSessionId=session_dict.pop(cls.FN.Session.ParentSessionId, None),
			Expiration=session_dict.pop(cls.FN.Session.Expiration, None),
			MaxExpiration=session_dict.pop(cls.FN.Session.MaxExpiration, None),
			ExpirationExtension=session_dict.pop(cls.FN.Session.ExpirationExtension, None),
			TrackId=session_dict.pop(cls.FN.Session.TrackId, None),
		)

	@classmethod
	def _deserialize_credentials_data(cls, session_dict):
		credentials_id = session_dict.pop(cls.FN.Credentials.Id, None)
		if credentials_id is None:
			return
		return CredentialsData(
			Id=credentials_id,
			CreatedAt=session_dict.pop(cls.FN.Credentials.CreatedAt, None),
			ModifiedAt=session_dict.pop(cls.FN.Credentials.ModifiedAt, None),
			Username=session_dict.pop(cls.FN.Credentials.Username, None),
			Email=session_dict.pop(cls.FN.Credentials.Email, None),
			Phone=session_dict.pop(cls.FN.Credentials.Phone, None),
			CustomData=session_dict.pop(cls.FN.Credentials.CustomData, None),
		)

	@classmethod
	def _deserialize_authentication_data(cls, session_dict):
		# BACK COMPAT for existing sessions with old login descriptor
		login_descriptor = session_dict.pop(cls.FN.Authentication.LoginDescriptor, None)
		if isinstance(login_descriptor, dict):
			login_descriptor = login_descriptor["id"]
		return AuthenticationData(
			AuthnTime=session_dict.pop(cls.FN.Authentication.AuthnTime, None),
			TOTPSet=session_dict.pop(cls.FN.Authentication.TOTPSet, None),
			ExternalLoginOptions=session_dict.pop(cls.FN.Authentication.ExternalLoginOptions, None),
			LoginDescriptor=login_descriptor,
			LoginFactors=session_dict.pop(cls.FN.Authentication.LoginFactors, None),
			AvailableFactors=session_dict.pop(cls.FN.Authentication.AvailableFactors, None),
			LastLogin=session_dict.pop(cls.FN.Authentication.LastLogin, None),
			IsAnonymous=session_dict.pop(cls.FN.Authentication.IsAnonymous, None),
			ImpersonatorCredentialsId=session_dict.pop(cls.FN.Authentication.ImpersonatorCredentialsId, None),
			ImpersonatorSessionId=session_dict.pop(cls.FN.Authentication.ImpersonatorSessionId, None),
		)

	@classmethod
	def _deserialize_authorization_data(cls, session_dict):
		authz = session_dict.pop(cls.FN.Authorization.Authz, None)
		return AuthorizationData(
			Authz=authz,
			AssignedTenants=session_dict.pop(cls.FN.Authorization.AssignedTenants, None),
		)

	@classmethod
	def _deserialize_oauth2_data(cls, session_dict):
		id_token = session_dict.pop(cls.FN.OAuth2.IdToken, None)
		if id_token is not None:
			try:
				id_token = id_token.decode("ascii")
			except UnicodeDecodeError:
				# Probably old ID token, encoded differently
				L.error("Cannot deserialize ID token", struct_data={"id_token": id_token})

		access_token = session_dict.pop(cls.FN.OAuth2.AccessToken, None)
		if access_token is not None:
			# Base64-encode the tokens for OIDC service convenience
			access_token = base64.urlsafe_b64encode(access_token).decode("ascii")

		refresh_token = session_dict.pop(cls.FN.OAuth2.RefreshToken, None)
		if refresh_token is not None:
			refresh_token = base64.urlsafe_b64encode(refresh_token).decode("ascii")

		return OAuth2Data(
			IDToken=id_token,
			AccessToken=access_token,
			RefreshToken=refresh_token,
			Scope=session_dict.pop(cls.FN.OAuth2.Scope, None),
			ClientId=session_dict.pop(cls.FN.OAuth2.ClientId, None),
			Nonce=session_dict.pop(cls.FN.OAuth2.Nonce, None),
			RedirectUri=session_dict.pop(cls.FN.OAuth2.RedirectUri, None),
		)

	@classmethod
	def _deserialize_cookie_data(cls, session_dict):
		sci = session_dict.pop(cls.FN.Cookie.Id, None)
		if sci is None:
			return None
		return CookieData(
			Id=base64.urlsafe_b64encode(sci).decode("ascii"),
			Domain=session_dict.pop(cls.FN.Cookie.Domain, None),
		)

	@classmethod
	def _deserialize_batman_data(cls, session_dict):
		token = session_dict.pop(cls.FN.Batman.Token, None)
		if token is None:
			return None
		return BatmanData(
			Token=token
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
		"authn_time": session_dict.get(SessionAdapter.FN.Authentication.AuthnTime),
		"login_descriptor": session_dict.get(SessionAdapter.FN.Authentication.LoginDescriptor),
		"login_factors": session_dict.get(SessionAdapter.FN.Authentication.LoginFactors),
		"tenants": session_dict.get(SessionAdapter.FN.Authorization.AssignedTenants),
		"resources": session_dict.get(SessionAdapter.FN.Authorization.Authz),
		"track_id": session_dict.get(SessionAdapter.FN.Session.TrackId),
	}
	psid = session_dict.get(SessionAdapter.FN.Session.ParentSessionId)
	if psid is not None:
		data["parent_session_id"] = psid

	client_id = session_dict.get(SessionAdapter.FN.OAuth2.ClientId)
	if client_id is not None:
		data["client_id"] = client_id
	scope = session_dict.get(SessionAdapter.FN.OAuth2.Scope)
	if scope is not None:
		data["scope"] = scope

	if session_dict.get(SessionAdapter.FN.OAuth2.AccessToken) is not None:
		data["access_token"] = True
	if session_dict.get(SessionAdapter.FN.Cookie.Id) is not None:
		data["cookie"] = True

	if session_dict.get(SessionAdapter.FN.Authentication.IsAnonymous) is True:
		data["anonymous"] = True

	impersonator_cid = session_dict.get(SessionAdapter.FN.Authentication.ImpersonatorCredentialsId)
	if impersonator_cid is not None:
		data["impersonator_cid"] = impersonator_cid
	impersonator_sid = session_dict.get(SessionAdapter.FN.Authentication.ImpersonatorSessionId)
	if impersonator_sid is not None:
		data["impersonator_sid"] = impersonator_sid

	return data
