# Design Considerations

## Openstack API irregularity

The openstack API repsonds different to admin users and non-admin users.
For non admin users, all requests are scoped to the project they are logged in to. For most request this can not be overridden. (i.e. it is not possible to lookup resource from another project, even when you have access to it)
For non admin users, not all requests are scoped to the project they are logged in to.

There is no api to determine if a user is an admin user.
If a user is an admin user can not be derived from the roles a user has, because the policy of when a user is an admin user can be configured on a per-service basis, using policy.json.

Logging in the current user into the project containing the resource works for regular users if they are properly authorized, but not for admin users.
Being admin is not a property of the user, but of the user/project combination. I.e. is an admin log in to another project he may no longer be admin.