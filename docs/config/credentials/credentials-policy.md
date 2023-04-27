---
layout: default
title: TeskaLabs SeaCat Auth Documentation
---

# Credentials policy

It is possible to configure which credentials fields are required for creating or registering new credentials.
You can also specify which credentials fields can be edited by whom.

## Configuration

To enable custom configuration, add the `policy_file` option to the service config file 
and specify the path to your policy file:

```ini
[seacatauth:credentials]
policy_file=/path/to/credentials-policy.json
```

## Policy options

The structure of the policy file follows a simple schema:

```json
{
    "<field_name>": {
        "<context>": "<policy>"
    }
}
```

It is possible to configure the following **fields**:
- `username`
- `email`
- `phone`

For all those fields there are two configurable **contexts**: credentials `creation` and `registration`.
Their **policy** options are:
- `disabled`: The field is not allowed in this context.
- `allowed`: The field is allowed, but not required in this context.
- `required`: The field is required in this context (and must not be empty).

The fields `email` and `phone` have an additional **context**: `editable_by`.
Its **policy** options are:
- `nobody`: The field is not editable, not even by a superuser.
- `admin_only`: The field is editable only by a superuser.
- `anybody`: The field is editable by anyone. This also makes it possible to update the field in one's own credentials.


### Policy file example

The following is the default policy configuration:

```json
{
	"username": {
		"creation": "required",
		"registration": "required"
	},
	"email": {
		"creation": "required",
		"registration": "required",
		"editable_by": "anybody"
	},
	"phone": {
		"creation": "allowed",
		"registration": "allowed",
		"editable_by": "anybody"
	}
}
```
