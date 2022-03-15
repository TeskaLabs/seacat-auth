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

	FNSessionType = "t"

	FNTenants = 'Tn'
	FNRoles = 'Rl'
	FNResources = 'Rs'
	FNAuthz = 'Authz'
	FNCredentialsId = 'Cid'
	FNCookieSessionId = 'SCI'

	FNLoginDescriptor = 'LD'
	FNAvailableFactors = 'AF'

	FNOAuth2AccessToken = 'oa.Ta'
	FNOAuth2IdToken = 'oa.Ti'
	FNOAuth2RefreshToken = 'oa.Tr'
	FNOAuth2Scope = 'oa.S'

	# Fields that are stored encrypted
	SensitiveFields = frozenset([
		FNOAuth2IdToken,
		FNOAuth2AccessToken,
		FNOAuth2RefreshToken,
		FNCookieSessionId,
	])

	EncryptedPrefix = b"$aescbc$"

	def __init__(self, session_svc, session_dict):

		self.SessionId = session_dict.pop('_id')
		self.Version = session_dict.pop('_v')
		self.CreatedAt = session_dict.pop('_c')
		self.ModifiedAt = session_dict.pop('_m')
		self.Expiration = session_dict.pop('exp')
		self.MaxExpiration = session_dict.pop('max_exp', None)
		self.TouchExtension = session_dict.pop('touch_ext', None)
		self.Type = session_dict.pop(self.FNSessionType)

		self.CredentialsId = session_dict.pop(self.FNCredentialsId, None)
		self.Authz = session_dict.pop(self.FNAuthz, None)
		self.LoginDescriptor = session_dict.pop(self.FNLoginDescriptor, None)
		self.AvailableFactors = session_dict.pop(self.FNAvailableFactors, None)

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

		sci = data.pop(self.FNCookieSessionId, None)
		if sci is not None:
			self.CookieSessionId = base64.urlsafe_b64encode(sci).decode('ascii')

		# OAuth2 / OpenId Connect
		o = data.pop('oa', None)
		if o is not None:
			self.OAuth2 = {}
			# Base64-encode the tokens for OIDC service convenience
			v = o.pop('Ta')
			if v is not None:
				self.OAuth2['access_token'] = base64.urlsafe_b64encode(v).decode('ascii')
			v = o.pop('Ti')
			if v is not None:
				self.OAuth2['id_token'] = base64.urlsafe_b64encode(v).decode('ascii')
			v = o.pop('Tr')
			if v is not None:
				self.OAuth2['refresh_token'] = base64.urlsafe_b64encode(v).decode('ascii')
			v = o.pop('S')
			if v is not None:
				self.OAuth2['scope'] = v

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
			self.CookieSessionId,
			self.Data,
			self.OAuth2,
		))
