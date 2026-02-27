# NAME

otpme-client - manage OTPme clients

# SYNOPSIS

**otpme-client** *command* \[*options*\] \[*client*\]

# DESCRIPTION

**otpme-client** manages client objects in the OTPme system. Clients are
connected either via RADIUS or LDAP. A special client is the OTPme SSO
portal, which provides Single Sign-On for web applications. Each client
is assigned an access group that controls which tokens are authorized,
and can optionally have addresses, secrets, and SSO configuration.

# COMMANDS

## Client Management

**add *client* \[*address*\]**  
Create a new client, optionally with an IP address.

**del *client***  
Delete a client.

**show \[*client*\]**  
Display client information. Without arguments, shows all clients.

**list \[*regex*\]**  
List clients, optionally filtered by regex pattern.

**enable *client***  
Enable a disabled client.

**disable *client***  
Disable a client without deleting it.

**rename *client* *new_name***  
Rename a client.

**move \[**--keep-acls**\] *client* *unit***  
Move client to a different unit.

**touch *client***  
Re-index the object to fix potential index problems.

## Access Group and Authorization

**access_group *client* \[*access_group*\]**  
Set or display the client's access group. The access group controls
which tokens are authorized to authenticate via this client.

**add_token *client* *token_path***  
Add a token to the client.

**remove_token *client* *token_path***  
Remove a token from the client.

**list_tokens *client***  
List tokens assigned to the client.

**add_role *client* *role***  
Add a role to the client.

**remove_role *client* *role***  
Remove a role from the client.

**list_roles *client***  
List roles assigned to the client.

## Login Control

**limit_logins *client***  
Limit logins to tokens and roles explicitly assigned to this client.

**unlimit_logins *client***  
Allow logins from all tokens authorized by the access group.

**secret *client* \[*secret*\]**  
Set or change the client secret (e.g. RADIUS shared secret).

**show_secret *client***  
Display the client secret.

## Address Management

**add_address *client* *address***  
Add an IP address to the client.

**del_address *client* *address***  
Remove an IP address from the client.

## Auth Cache

**enable_auth_cache *client***  
Enable authentication caching for this client.

**disable_auth_cache *client***  
Disable authentication caching.

**auth_cache_timeout *client* *timeout***  
Set authentication cache timeout.

## SSO Configuration

**enable_sso *client***  
Enable SSO (Single Sign-On) for this client.

**disable_sso *client***  
Disable SSO for this client.

**sso_name *client* *name***  
Set the SSO display name for this client.

**sso_logo *client* *image_path***  
Set the SSO logo image for this client.

**dump_sso_logo *client***  
Export SSO logo as base64.

**del_sso_logo *client***  
Delete the SSO logo.

**login_url *client* *url***  
Set the client login URL.

**helper_url *client* *url***  
Set the SSO helper URL.

**enable_sso_popup *client***  
Enable SSO popup for this client.

**disable_sso_popup *client***  
Disable SSO popup for this client.

## Policy Management

**add_policy *client* *policy***  
Attach a policy to the client.

**remove_policy *client* *policy***  
Remove a policy from the client.

**list_policies *client***  
List policies attached to the client.

## ACL Management

**add_acl *client* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *client* *acl***  
Remove an access control entry.

**show_acls *client***  
Display all ACLs for the client.

**enable_acl_inheritance *client***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *client***  
Disable ACL inheritance.

## Configuration and Attributes

**config \[**-d**\] *client* *parameter* \[*value*\]**  
Set or display a configuration parameter. Use **-d** to delete (reset to
default).

**show_config *client* \[*parameter*\]**  
Show all configuration parameters.

**description *client* \[*description*\]**  
Set client description.

**add_extension *client* *extension***  
Add an extension to the client.

**remove_extension *client* *extension***  
Remove an extension.

**add_attribute *client* *attribute*=*value***  
Add an LDAP attribute.

**del_attribute *client* *attribute*=*value***  
Remove an LDAP attribute.

**add_object_class *client* *class***  
Add an LDAP object class.

**del_object_class *client* *class***  
Remove an LDAP object class.

## Import/Export

**export \[**--password** *PASS*\] *client***  
Export client configuration.

**remove_orphans *client***  
Remove orphaned object references.

# OPTIONS

## Display Options

**-a**  
Show all clients (across all units).

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

**--policy-limit *N***  
Limit number of policies shown.

**--sort-by *FIELD***  
Sort output by field.

**--reverse**  
Reverse sort order.

**--raw**  
Output without headers/borders.

**--csv**  
Output as CSV.

**--csv-sep *SEP***  
CSV separator character.

**--attribute *ATTR***  
Display specific attribute in list command.

## General Options

**--keep-acls**  
Preserve ACLs when moving client.

**--password *PASS***  
Password for encrypting exports.

Global options are available for all commands. See **otpme**(1) for
details.

# CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and
displayed with **show_config**. For a complete description of all
available parameters and their applicable object types, see
**otpme**(7).

# EXAMPLES

## Creating and Configuring Clients

**otpme-client add radius_gw 10.0.0.1**  
Create client with IP address

**otpme-client access_group radius_gw vpn**  
Assign access group to client

**otpme-client secret radius_gw**  
Set RADIUS shared secret

## Managing Addresses

**otpme-client add_address radius_gw 10.0.0.2**  
Add additional address

**otpme-client del_address radius_gw 10.0.0.1**  
Remove address

## SSO Configuration

**otpme-client enable_sso webapp**  
Enable SSO for web application

**otpme-client sso_name webapp My Application**  
Set SSO display name

**otpme-client login_url webapp https://app.example.com/login**  
Set login URL

## Login Control

**otpme-client limit_logins radius_gw**  
Limit logins to explicitly assigned tokens

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(7), **otpme-accessgroup**(1), **otpme-token**(1),
**otpme-role**(1), **otpme-policy**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
