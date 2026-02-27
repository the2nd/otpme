# NAME

otpme-node - manage OTPme nodes

# SYNOPSIS

**otpme-node** *command* \[*options*\] \[*node*\]

# DESCRIPTION

**otpme-node** manages node objects in the OTPme system. Nodes are the
servers that run OTPme daemons and provide authentication, management,
and synchronization services to the realm. Nodes have certificates, can
be configured with tokens, roles, and dynamic groups.

# COMMANDS

## Node Management

**add *node***  
Create a new node.

**del *node***  
Delete a node.

**show \[*node*\]**  
Display node information. Without arguments, shows all nodes.

**list \[*regex*\]**  
List nodes, optionally filtered by regex pattern.

**enable *node***  
Enable a disabled node.

**disable *node***  
Disable a node without deleting it.

**move \[**--keep-acls**\] *node* *unit***  
Move node to a different unit.

**touch *node***  
Re-index the object to fix potential index problems.

## Token and Role Assignment

**add_token \[**-i** *interfaces*\] \[**--no-auto-sign**\] \[**--sign** **--tags** *tag1,tag2*\] *node* *token_path***  
Add a token to the node. Use **-i** to limit login to specific
interfaces (e.g. tty, gui, ssh).

**remove_token \[**--keep-sign**\] *node* *token_path***  
Remove a token from the node.

**list_tokens *node***  
List tokens assigned to the node.

**add_role *node* *role***  
Add a role to the node.

**remove_role *node* *role***  
Remove a role from the node.

**list_roles *node***  
List roles assigned to the node.

## Login Control

**limit_logins *node***  
Limit logins to tokens and roles explicitly assigned to this node.

**unlimit_logins *node***  
Allow logins from all authorized tokens.

## User and Group Listing

**list_users *node***  
List users on the node.

**list_dynamic_groups *node***  
List dynamic groups of the node.

## Dynamic Groups

Dynamic groups are local Linux groups (e.g. plugdev) that exist on hosts
and nodes. Users are automatically added to these groups when they log
in via the OTPme PAM module. This is most commonly used on hosts where
users log in interactively.

**add_dynamic_group *node* *group***  
Add a dynamic group to the node.

**remove_dynamic_group *node* *group***  
Remove a dynamic group from the node.

## Realm Join/Leave

**enable_jotp *node***  
Enable realm join via JOTP.

**disable_jotp *node***  
Disable realm join via JOTP.

**enable_lotp *node***  
Enable realm leaving via LOTP.

**disable_lotp *node***  
Disable realm leaving via LOTP.

**enable_jotp_rejoin *node***  
Enable printing of rejoin JOTP on realm leave.

**disable_jotp_rejoin *node***  
Disable printing of rejoin JOTP on realm leave.

## Certificate Operations

**dump_cert *node***  
Export the node certificate to stdout.

**dump_ca_chain *node***  
Export the CA certificate chain of the node cert to stdout.

**renew_cert *node***  
Renew the node certificate.

**public_key *node* \[*public_key*\]**  
Set or display the node's public key.

## Vote Script

**vote_script *node* *vote_script***  
Set the node vote script.

**enable_vote_script *node***  
Enable the node vote script.

**disable_vote_script *node***  
Disable the node vote script.

## SSH

**get_ssh_authorized_keys *node* \[*user*\]**  
Get SSH authorized keys for the node, optionally for a specific user.

## Policy Management

**add_policy *node* *policy***  
Attach a policy to the node.

**remove_policy *node* *policy***  
Remove a policy from the node.

**list_policies *node***  
List policies attached to the node.

## ACL Management

**add_acl *node* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *node* *acl***  
Remove an access control entry.

**show_acls *node***  
Display all ACLs for the node.

**enable_acl_inheritance *node***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *node***  
Disable ACL inheritance.

## Configuration and Attributes

**config \[**-d**\] *node* *parameter* \[*value*\]**  
Set or display a configuration parameter. Use **-d** to delete (reset to
default).

**show_config *node* \[*parameter*\]**  
Show all configuration parameters.

**description *node* \[*description*\]**  
Set node description.

## Import/Export

**export \[**--password** *PASS*\] *node***  
Export node configuration.

**remove_orphans *node***  
Remove orphaned object references.

# OPTIONS

## Display Options

**-a**  
Show all nodes (across all units).

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

**--role-limit *N***  
Limit number of roles shown.

**--token-limit *N***  
Limit number of tokens shown.

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

## Token Options

**-i *interfaces***  
Limit login to given interfaces (e.g. tty, gui, ssh).

**--sign**  
Sign the object with default tags.

**--tags *tag1,tag2***  
Add tags to signature.

**--no-auto-sign**  
Do not automatically sign when adding a token.

**--keep-sign**  
Do not remove any signature when removing a token.

## General Options

**--keep-acls**  
Preserve ACLs when moving node.

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

## Managing Nodes

**otpme-node add node2**  
Create a new node

**otpme-node enable_jotp node2**  
Enable realm join via JOTP

## Token Assignment

**otpme-node add_token node2 admin/totp**  
Allow admin's TOTP token to login on node

**otpme-node add_token -i ssh node2 admin/ssh_key**  
Allow admin's SSH key only for SSH interface

## Certificate Operations

**otpme-node dump_cert node2**  
Export node certificate

**otpme-node renew_cert node2**  
Renew the node certificate

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-host**(1), **otpme-token**(1),
**otpme-role**(1), **otpme-ca**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
