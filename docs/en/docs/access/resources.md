---
title: Resources
---

# Resources

Resources are the most basic unit of authorization. They are single and specific access permissions.

!!! note "How to use resources"

    * To grant credentials access to resources, group resources into a role, then assign the role to credentials. In other words, you cannot assign resources directly to credentials; credentials can have access to a resource only through a role.
    * You can assign the same resource to several roles.
    * A role can have multiple resources. A role can be assigned to multiple credentials.


On the Resources screen, you can see:

* Resource ID: The name of the resource
* Description: A user-created and human-readable description of what permission the resource grants
* Created at: Date and time the resource was created

## Creating a resource

1. From the Resources screen, click **New resource**.
2. Name the resource, enter a short description, and click **Create resource**.

## Deleted resources

1. To view deleted resources, click **Deleted resources** on the Resources screen.
2. To renew a resource (make it active again), click the circular arrow at the end of the resource's line.

## Included resources

The following resources are automatically available in an installation of SeaCat Auth:

* `seacat:tenant:create`: Grants right to create a new tenant	
* `seacat:role:assign`: Assign and unassign tenant roles.
* `seacat:role:edit`: Create, edit and delete tenant roles. This does not enable the bearer to assign SeaCat system resources.	
* `seacat:role:access`: Search tenant roles, view role detail and list role bearers.	
* `seacat:tenant:assign`: Assign and unassign tenant members, invite new users to tenant.	
* `seacat:tenant:delete`: Delete tenant.	
* `seacat:tenant:edit`: Edit tenant data.	
* `seacat:tenant:access`: List tenants, view tenant detail and see tenant members.	
* `seacat:client:edit`: Edit and delete clients.	
* `seacat:client:access`: List clients and view client details.	
* `seacat:resource:edit`: Edit and delete resources.	
* `seacat:resource:access`: List resources and view resource details.
* `seacat:session:terminate`: Terminate sessions.
* `seacat:session:access`: List sessions and view session details.
* `seacat:credentials:edit`: Edit and suspend credentials.
* `seacat:credentials:access`: List credentials and view credentials details.
