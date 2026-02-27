# OTPME-ROLE(1)

## NAME

otpme-role - manage OTPme roles

## SYNOPSIS

**otpme-role**
*command*
[*options*] [*role*]

## DESCRIPTION

**otpme-role**
manages roles in the OTPme system. Roles are groups of tokens or other roles that can be nested.

## COMMANDS

### Role Management

**add [**--groups** *group1,group2*] [**--roles** *role1,role2*] *role***
:   Create a new role. Optionally add it directly to groups or other roles.

**del *role***
:   Delete a role.

**show [*role*]**
:   Display role information. Without arguments, shows all roles.

**list [*regex*]**
:   List roles, optionally filtered by regex pattern.

**enable *role***
:   Enable a disabled role.

**disable *role***
:   Disable a role without deleting it.

**rename *role* *new_name***
:   Rename a role.

**move [**--keep-acls**] *role* *unit***
:   Move role to a different unit.

**touch *role***
:   Re-index the object to fix potential index problems.

### Token Assignment

**add_token [**-i** *interfaces*] [**--no-auto-sign**] [**--sign** **--tags** *tag1,tag2*] *role* *token_path***
:   Add a token to the role. Use **-i** to limit login to specific interfaces (e.g. tty, gui, ssh).

**remove_token [**--keep-sign**] *role* *token_path***
:   Remove a token from the role.

**list_tokens *role***
:   List tokens assigned to the role.

### Role Nesting

**add_role *role* *child_role***
:   Add a child role to this role.

**remove_role *role* *child_role***
:   Remove a child role from this role.

**list_roles [**-r**] *role***
:   List roles assigned to the role. Use **-r** for recursive listing.

### User and Group Listing

**list_users *role***
:   List users of the role.

**list_dynamic_groups *role***
:   List dynamic groups of the role.

### Dynamic Groups

**add_dynamic_group *role* *group***
:   Add a dynamic group to the role.

**remove_dynamic_group *role* *group***
:   Remove a dynamic group from the role.

### Sync Users

**add_sync_user *role* *user***
:   Add a sync user to the role.

**remove_sync_user *role* *user***
:   Remove a sync user from the role.

**list_sync_users *role***
:   List sync users of the role.

### Policy Management

**add_policy *role* *policy***
:   Attach a policy to the role.

**remove_policy *role* *policy***
:   Remove a policy from the role.

**list_policies *role***
:   List policies attached to the role.

### ACL Management

**add_acl *role* *owner_type* *owner* *acl***
:   Add an access control entry.

**del_acl *role* *acl***
:   Remove an access control entry.

**show_acls *role***
:   Display all ACLs for the role.

**enable_acl_inheritance *role***
:   Enable ACL inheritance from parent objects.

**disable_acl_inheritance *role***
:   Disable ACL inheritance.

### Extension and Attribute Management

**add_extension *role* *extension***
:   Add an extension to the role.

**remove_extension *role* *extension***
:   Remove an extension from the role.

**add_attribute *role* *attribute*=*value***
:   Add an LDAP attribute to the role.

**del_attribute *role* *attribute*=*value***
:   Remove an LDAP attribute from the role.

**add_object_class *role* *class***
:   Add an LDAP object class to the role.

**del_object_class *role* *class***
:   Remove an LDAP object class from the role.

**show_ldif [**-a** *attributes*] *role***
:   Show LDIF representation of the role. Use **-a** to show only specific attributes.

### Configuration and Attributes

**config [**-d**] *role* *parameter* [*value*]**
:   Set or display a configuration parameter. Use **-d** to delete (reset to default).

**show_config *role* [*parameter*]**
:   Show all configuration parameters.

**description *role* [*description*]**
:   Set role description.

### Import/Export

**export [**--password** *PASS*] *role***
:   Export role configuration.

**remove_orphans *role***
:   Remove orphaned object references.

## OPTIONS

### Display Options

**-a**
:   Show all roles (across all units).

**-z *SIZE***
:   Limit output size.

**--fields *FIELD1,FIELD2***
:   Display only specified fields.

**--token-limit *N***
:   Limit number of tokens shown.

**--role-limit *N***
:   Limit number of roles shown.

**--accessgroup-limit *N***
:   Limit number of access groups shown.

**--group-limit *N***
:   Limit number of groups shown.

**--policy-limit *N***
:   Limit number of policies shown.

**--sort-by *FIELD***
:   Sort output by field.

**--reverse**
:   Reverse sort order.

**--raw**
:   Output without headers/borders.

**--csv**
:   Output as CSV.

**--csv-sep *SEP***
:   CSV separator character.

**--attribute *ATTR***
:   Display specific attribute in list command.

### Token Options

**-i *interfaces***
:   Limit login to given interfaces (e.g. tty, gui, ssh).

**--sign**
:   Sign the object with default tags.

**--tags *tag1,tag2***
:   Add tags to signature.

**--no-auto-sign**
:   Do not automatically sign when adding a token.

**--keep-sign**
:   Do not remove any signature when removing a token.

### General Options

**--keep-acls**
:   Preserve ACLs when moving role.

**--password *PASS***
:   Password for encrypting exports.

**-r**
:   List roles recursively.

Global options are available for all commands. See
[otpme(1)](otpme.md)
for details.

## CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and displayed with **show_config**.
For a complete description of all available parameters and their applicable object types, see
[otpme(7)](otpme.7.md).

## EXAMPLES

### Managing Roles

**otpme-role add admins**
:   Create a new role

**otpme-role add --groups sysadmins --roles operators**
:   Create a role and add it to groups and roles

### Token Assignment

**otpme-role add_token admins admin/totp**
:   Add admin's TOTP token to the role

**otpme-role add_token -i ssh admins admin/ssh_key**
:   Add SSH key for SSH interface only

### Role Nesting

**otpme-role add_role super_admins admins**
:   Add admins role as child of super_admins

**otpme-role list_roles -r super_admins**
:   List all nested roles recursively

### Policy Assignment

**otpme-role add_policy admins require_2fa**
:   Attach a policy to the role

## FILES

*/var/lib/otpme/*
:   OTPme data directory

## SEE ALSO

[otpme(1)](otpme.md),
[otpme(7)](otpme.7.md),
[otpme-user(1)](otpme-user.md),
[otpme-token(1)](otpme-token.md),
[otpme-group(1)](otpme-group.md),
[otpme-accessgroup(1)](otpme-accessgroup.md),
[otpme-policy(1)](otpme-policy.md)

## AUTHOR

the2nd <the2nd@otpme.org>

## NOTE

This manual page was created with AI assistance.

## COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
