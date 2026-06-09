---
title: Reset user password
---

# Reset user password via CLI

The `reset-password.py` script allows administrators to reset a user's password directly in the database. This is useful when:

- A user has forgotten their password and cannot use the self-service password reset
- You need to quickly set a temporary password for a new user
- Troubleshooting authentication issues

!!! note "MongoDB provider only"
    This script only works for users stored in the default MongoDB provider. It does not work for users authenticated via external providers such as LDAP, Active Directory, or OAuth.


## Running in Docker

The script is not included in the SeaCat Auth Docker image. To run it, you need to download the script and copy it into a running container.

### Prerequisites

- A running SeaCat Auth container (in the examples below, the container is named `seacat-auth`)
- Access to the same MongoDB database that SeaCat Auth is configured to use

### Step 1: Download the script

Download the script from the GitHub repository:

```bash
curl -O https://raw.githubusercontent.com/TeskaLabs/seacat-auth/main/scripts/reset-password.py
```

### Step 2: Copy the script into the container

Copy the downloaded script into the running SeaCat Auth container:

```bash
docker cp reset-password.py seacat-auth:/tmp/reset-password.py
```

### Step 3: Execute the script

Run the script inside the container using `docker exec`:

```bash
docker exec -it seacat-auth python3 /tmp/reset-password.py
```

The script will:

1. Connect to MongoDB using the configuration from `/conf/seacatauth.conf`
2. Prompt you for the username to reset
3. Display the matching user details for confirmation
4. Ask for the new password (entered twice for verification)
5. Update the password hash in the database

### Step 4: Clean up (optional)

Remove the script from the container when done:

```bash
docker exec seacat-auth rm /tmp/reset-password.py
```

### Example session

```
$ curl -O https://raw.githubusercontent.com/TeskaLabs/seacat-auth/main/scripts/reset-password.py
$ docker cp reset-password.py seacat-auth:/tmp/reset-password.py
$ docker exec -it seacat-auth python3 /tmp/reset-password.py
Enter username to reset password for: jsmith

User found:
  ID:         6478a2b3c4d5e6f7a8b9c0d1
  Username:   jsmith
  Email:      john.smith@example.com
  Phone:      N/A
  Suspended:  False

Is this the correct user? [y/N]: y
Enter new password:
Confirm new password:

Password successfully updated for user 'jsmith'.
```


## Running outside Docker

If you need to run the script outside of a container (for example, during development):

```bash
python scripts/reset-password.py -c /path/to/seacatauth.conf
```

The `-c` (or `--config`) option specifies the path to the SeaCat Auth configuration file. If omitted, it defaults to `/conf/seacatauth.conf`.


## Configuration requirements

The script reads MongoDB connection details from the `[mongo]` section of the configuration file:

```ini
[mongo]
uri=mongodb://localhost:27017
database=seacat_auth
```

Ensure the configuration file is readable by the user running the script (or the container).
