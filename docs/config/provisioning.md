---
layout: default
title: TeskaLabs SeaCat Auth Documentation
---

# Provisioning mode

When you install a new clean instance of SeaCat Auth, there is no conventional of logging in since there are no user accounts.
Provisioning mode creates temporary superuser credentials which can be used to log in and create an ordinary account for yourself.


## Running SeaCat Auth in provisioning mode

There are two ways to activate providioning mode:
- The first option is to execute `seacatauth.py` with `--provisioning` argument

```shell
python3 seacatauth.py -c /conf/seacatauth.conf --provisioning
```

- The other option is to set the `SEACAT_AUTH_PROVISIONING` environment variable to `1` or `TRUE`, export it and run SeaCat Auth. This is easily done in `docker-compose.yml`:

```yaml
seacat-auth-svc:
  ...
  environment:
    - SEACAT_AUTH_PROVISIONING=1
```


## Logging in

When you start the provisioning mode, the following text will be printed into the SeaCat Auth log:

```
SeaCat Auth is running in provisioning mode.

Use the following credentials to log in:

	USERNAME:   superuser
	PASSWORD:   **************

```

Use those credentials to log in.

In the WebUI you will see that a provisioning tenant and a provisioning role have been created. These are temporary and will be automatically deleted when the app is stopped.

**`NOTE`** The superuser credentials are deleted and recreated with a new password everytime the app is restarted.


## Setting up the environment

- **Create a tenant.** Any user must have at least one tenant assigned to them to be allowed into SeaCat WebUI.
- **Create a superuser role.** To be able to execute some administrative commands it is necessary to have a superuser role assigned. This role must be created as **global**. After creating it, open the role detail and add the `authz:superuser` resource into the role. It is advisable to have at least one user with superuser rights.
- `OPTIONAL` **Create a seacat-user role.** If you are using resource-based authorization in SeaCat WebUI or API, it is useful to have a role that allows its bearer to access the SeaCat WebUI but doesn't grant them superuser administrative rights. Create a role and assign the `seacat:access` resource to it.
- **Create a user account.** The password will be sent via email or SMS, depending on what contact info you fill in. **Make sure that your SMTP or SMS provider is set up properly in SeaCat Auth config.**
- Open the user detail and **assign the tenant and the role** that you created earlier.
- You can now log out of the provisioning superuser session.
- Check if you have received the reset password link for your new credentials. Proceed to reset the password and then log in!

**`NOTE`** Do not assign the provisioning tenant or the provisioning superuser role to any other user, as it is temporary and will be deleted when the app is restarted and provisioning ends.

## Disable provisioning mode

To disable provisioning mode, simply run the app without the `--provisioning` flag and with `SEACAT_AUTH_PROVISIONING` set to `0` or unset completely (deleted from `docker-compose.yml`).
