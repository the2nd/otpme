# OTPME-POOL(1)

## NAME

otpme-pool - manage OTPme node pools

## SYNOPSIS

**otpme-pool**
*command*
[*options*] [*pool*]

## DESCRIPTION

**otpme-pool**
manages node pools in the OTPme system. A pool defines which nodes are used for a share.

## COMMANDS

### Pool Management

**add *pool***
:   Create a new pool.

**del *pool***
:   Delete a pool.

**show [*pool*]**
:   Display pool information.

**list [*regex*]**
:   List pools, optionally filtered by regex pattern.

**enable *pool***
:   Enable a disabled pool.

**disable *pool***
:   Disable a pool without deleting it.

**rename *pool* *new_name***
:   Rename a pool.

**move [**--keep-acls**] *pool* *unit***
:   Move pool to a different unit.

**touch *pool***
:   Re-index the object to fix potential index problems.

### Node Management

**add_node *pool* *node***
:   Add a node to the pool.

**remove_node *pool* *node***
:   Remove a node from the pool.

**list_nodes *pool***
:   List nodes in the pool.

### Policy Management

**add_policy *pool* *policy***
:   Attach a policy to the pool.

**remove_policy *pool* *policy***
:   Remove a policy from the pool.

**list_policies *pool***
:   List policies attached to the pool.

### ACL Management

**add_acl *pool* *owner_type* *owner* *acl***
:   Add an access control entry.

**del_acl *pool* *acl***
:   Remove an access control entry.

**show_acls *pool***
:   Display all ACLs for the pool.

**enable_acl_inheritance *pool***
:   Enable ACL inheritance from parent objects.

**disable_acl_inheritance *pool***
:   Disable ACL inheritance.

### Configuration

**description *pool* [*description*]**
:   Set pool description.

### Import/Export

**export [**--password** *PASS*] *pool***
:   Export pool configuration.

**remove_orphans *pool***
:   Remove orphaned object references.

## OPTIONS

### Display Options

**-a**
:   Show all pools.

**-z *SIZE***
:   Limit output size.

**--fields *FIELD1,FIELD2***
:   Display only specified fields.

**--node-limit *N***
:   Limit number of nodes shown.

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

### General Options

**--keep-acls**
:   Preserve ACLs when moving pool.

**--password *PASS***
:   Password for encrypting exports.

Global options are available for all commands. See
[otpme(1)](otpme.md)
for details.

## EXAMPLES

**otpme-pool add europe**
:   Create a pool

**otpme-pool add_node europe node-eu-1**
:   Add a node to the pool

**otpme-pool list_nodes europe**
:   List nodes in the pool

## FILES

*/var/lib/otpme/*
:   OTPme data directory

## SEE ALSO

[otpme(1)](otpme.md),
[otpme(7)](otpme.7.md),
[otpme-share(1)](otpme-share.md),
[otpme-node(1)](otpme-node.md)

## AUTHOR

the2nd <the2nd@otpme.org>

## NOTE

This manual page was created with AI assistance.

## COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
