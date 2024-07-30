---
title: Roles
---

# Roles

## Tenant roles

Tenant roles exist and have effect only within a specific tenant. 
They can only be assigned to users that are members of that tenant.
Their ID always starts with the name of their tenant followed by slash and the role name (`$TENANT_ID/$ROLE_NAME`), 
for example `acmecorp/admin`.

To edit the privileges of a tenant role, it is necessary to have access to resource `seacat:role:edit`.

## Global roles

Global roles exist above tenants.
When assigned to a user, a global role has effect across all the user's tenants.
Their ID starts with an asterisk followed by slash and the role name (`*/$ROLE_NAME`), 
for example `*/superuser`.

To edit the privileges of a global role, it is necessary to have superuser privileges.

### Global roles with tenant propagation

When creating a global role, there is an option to mark it as "Propagated to tenants".
Propagated global roles behave as common global roles, plus they create their virtual copy (or a "link", to be more precise) in every tenant.
This allows for defining a role globally, while also being able to assign it to users independently in every tenant.
The ID of such virtual propagated role starts with the name of their tenant followed by slash, **a tilde** and the global role name (`$TENANT_ID/~$ROLE_NAME`),
for example if the global role is called  `*/reader`, its virtual copy in tenant `acmecorp` will have the ID `acmecorp/~reader`.

The privileges of virtual tenant roles are not editable, they are always in sync with their global role.
To change the privileges, it is necessary to edit the global role.
The changes will be propagated to all tenants.
