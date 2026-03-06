---
title: External Login
---

# External Login

## Basic Example

```ini
[seacatauth:oauth2:google]
client_id=YOUR_GOOGLE_CLIENT_ID
client_secret=YOUR_GOOGLE_CLIENT_SECRET
register_unknown_at_login=true   # Auto-register unknown users
pair_unknown_at_login=false      # Pair with existing account if email matches
lowercase_email=true             # Normalize email to lowercase

[seacatauth:saml:teskalabs]
idp_metadata_url=https://idp.example.com/metadata
register_unknown_at_login=true
pair_unknown_at_login=true
tenant=teskalabs                 # Assign new users to a tenant
assume_email_is_verified=true    # Treat email as verified
```

## Key Options

- `register_unknown_at_login`: Auto-register users not yet known to SeaCat Auth.
- `pair_unknown_at_login`: Pair unknown external accounts with existing users by email.
- `tenant`: Assign a tenant to new users from this provider.
- `lowercase_sub`, `lowercase_username`, `lowercase_email`: Normalize these attributes to lowercase if set to `true`.
- `assume_email_is_verified`: Treat email as verified if not provided by the external provider.

User attributes are normalized to: `sub`, `username`, `email`, `phone`, and `name`.


# Available External Login Providers

SeaCat Auth supports the following external login providers:

- **OAuth2**: Google, Facebook, GitHub, Apple, Office365, MojeID, and other generic OAuth2 providers
- **SAML**: Any SAML 2.0-compliant identity provider
- **OpenID Connect**: Any OIDC-compliant provider

Below are minimal configuration examples for each supported provider type:

### Google (OAuth2)
```ini
[seacatauth:oauth2:google]
client_id=YOUR_GOOGLE_CLIENT_ID
client_secret=YOUR_GOOGLE_CLIENT_SECRET
```

### Facebook (OAuth2)
```ini
[seacatauth:oauth2:facebook]
client_id=YOUR_FACEBOOK_CLIENT_ID
client_secret=YOUR_FACEBOOK_CLIENT_SECRET
```

### GitHub (OAuth2)
```ini
[seacatauth:oauth2:github]
client_id=YOUR_GITHUB_CLIENT_ID
client_secret=YOUR_GITHUB_CLIENT_SECRET
```

### Apple (OAuth2)
```ini
[seacatauth:oauth2:appleid]
client_id=YOUR_APPLE_CLIENT_ID
client_secret=YOUR_APPLE_CLIENT_SECRET
```

### Office365 (OAuth2)
```ini
[seacatauth:oauth2:office365]
client_id=YOUR_OFFICE365_CLIENT_ID
client_secret=YOUR_OFFICE365_CLIENT_SECRET
```

### MojeID (OAuth2)
```ini
[seacatauth:oauth2:mojeid]
client_id=YOUR_MOJEID_CLIENT_ID
client_secret=YOUR_MOJEID_CLIENT_SECRET
```

### Generic OAuth2 Provider
```ini
[seacatauth:oauth2:custom]
client_id=YOUR_CLIENT_ID
client_secret=YOUR_CLIENT_SECRET
authorization_url=PROVIDER_AUTH_URL
token_url=PROVIDER_TOKEN_URL
userinfo_url=PROVIDER_USERINFO_URL
```

### SAML Provider
```ini
[seacatauth:saml:youridp]
idp_metadata_url=https://idp.example.com/metadata
```
