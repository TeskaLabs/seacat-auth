# External login

Seacat Auth supports login via third party authentication providers.
This allows users to use their Google or Github account to log into Seacat Auth.

At this moment, the following login providers are available:

- Google
- Office 365
- Github
- Moje ID

## Usage

Once configured, external login options are available on the login screen 
as an alternative to the standard Seacat Auth login.

Any user can enable or disable their external login options on their _My account_ screen. 

## Setting up external login providers

### Register your Seacat Auth application

Once you select which login provider you want to set up, proceed to their website 
to register your Seacat Auth application.
You will receive **Client ID** and **Client secret** which you will use in Seacat Auth configuration.

### Provide redirect URIs

Most OAuth2 providers will require you to specify a list of exact **authorized redirect URIs**.
If that is the case, you need to provide two URIs in the following format:

```
<SEACAT_PUBLIC_API_BASE_URL>/public/ext-login/<LOGIN_PROVIDER>
<SEACAT_PUBLIC_API_BASE_URL>/public/ext-login-add/<LOGIN_PROVIDER>
```

*For example, if your public Seacat Auth API is running at `https://auth.example.xyz/auth/api/seacat_auth/` 
and you want to configure login with `google`, add these addresses to the list of authorized redirect URIs
in Google API Credentials.*

```
https://auth.example.xyz/auth/api/seacat_auth/public/ext-login/google
https://auth.example.xyz/auth/api/seacat_auth/public/ext-login-add/google
```

Other providers (e.g. Github) do not require a list of exact URIs but rather a single path 
that all of your redirect URIs will start with.
In such cases just provide the base URL of your Seacat Auth public API, for example

```
https://auth.example.xyz/auth/api/seacat_auth/public/
```

### Configure Seacat Auth

Finally, you can add a section defining your external login provider in the Seacat Auth config file.
You will need at least the **Client ID** and the **Client secret** that you received at your login provider. 

The config section name is always in the format `[seacatauth:<EXTERNAL_PROVIDER_TYPE>]`.
The external provider types are:
- Google: `google`
- Office 365: `office365`
- Github: `github`
- Moje ID: `mojeid`

See below for config examples of the individual login providers.

## Configuration examples

### Google

Register your Seacat Auth app in [Google API Credentials](https://console.cloud.google.com/apis/credentials).

```ini
[seacatauth:google]
client_id=a2c4e6...
client_secret=1b3d5f...
```

### Office 365

Register your Seacat Auth app in [Azure Active Directory](https://portal.azure.com).

```ini
[seacatauth:office365]
tenant_id=def123...
client_id=a2c4e6...
client_secret=1b3d5f...
```

### Github

Register your Seacat Auth app in your [Github developer settings](https://github.com/settings/developers).

```ini
[seacatauth:github]
client_id=a2c4e6...
client_secret=1b3d5f...
```

### Moje ID

Sign up for a [Moje ID provider account](https://www.mojeid.cz/cs/pro-poskytovatele/jak-zavest/).
Follow [their documentation](https://www.mojeid.cz/dokumentace/html/ImplementacePodporyMojeid/OpenidConnect/PrehledKroku.html) 
to obtain client ID and secret.

```ini
[seacatauth:mojeid]
client_id=a2c4e6...
client_secret=1b3d5f...
```
