# NAME

otpme-trash - list, restore and remove what was deleted

# SYNOPSIS

**otpme-trash** *command* \[*options*\] \[*trash_id*\]

# DESCRIPTION

An object that is deleted goes into the trash first, unless **del** is
given **--no-trash**. One deletion makes one entry, with every object it
took along, e.g. a user and its tokens. An entry is named by its trash
ID, the time of the deletion and a UUID, and it says which token deleted
it.

The trash is on the nodes: the node that deletes writes the entry, and
the cluster writes it to the other nodes of the site. **restore**,
**del** and **empty** count on all of them in the same way.

Nothing leaves the trash by itself. It grows until somebody runs **del**
or **empty**.

# COMMANDS

An admin sees and handles every entry of the trash. Anyone else only the
entries of what their own token deleted; there is no ACL for it.

**show \[**-z** *n*\] \[**--fields** *field1,field2*\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\]**  
List the entries, newest first: the trash ID, the objects in it, who
deleted them and when. One deletion is one entry, with every object it
deleted, e.g. a user and its tokens. **-z** shows that many entries
(default: 10), and the last line says how many there are. The fields are
**trash_id**, **object**, **deleted_by** and **deletion_date**;
**--raw** leaves the header and the borders out, **--csv** prints one
row per line with **;** between the columns and the trash ID in every
row, and **--csv-sep** uses another separator.

**restore \[**--keep**\] \[**--objects** *oid1,oid2*\] *trash_id***  
Put the objects of the entry back, units before what is in them. A token
comes back into the roles, groups and access groups it was in. An object
with the UUID of one that exists is refused, and one with the name of
one that exists is asked about first; the global option **-f**
overwrites it. **--objects** restores only those, by the OIDs **show**
lists. The entry is removed when all of its objects are back, unless
**--keep** is given; after **--objects** it stays.

**dump *trash_id* *object***  
Write the configuration of one object of the entry to stdout, by the OID
**show** lists. Only an admin may.

**del *trash_id***  
Remove the entry for good.

**empty**  
Remove every entry for good. Anyone else than an admin removes only
their own, and only where **allow_non_admin_trash_empty** allows it
(default: true).

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# EXAMPLES

**otpme-trash show**  
The 10 newest entries you may see.

**otpme-trash show -z 100 --csv --fields trash_id,object**  
The 100 newest, one object per line, for a script.

**otpme-trash restore 1774709126.6068273-a48eb24e-4238-4b40-b5b8-e4b863a43d7c**  
Put back what that deletion took, e.g. a user with its tokens, and
remove the entry.

**otpme-trash restore --objects 'token\|example.org/berlin/alice/login' 1774709126.6068273-a48eb24e-4238-4b40-b5b8-e4b863a43d7c**  
Put back only that token; the entry stays for the rest.

**otpme-trash dump 1774709126.6068273-a48eb24e-4238-4b40-b5b8-e4b863a43d7c 'user\|example.org/berlin/users/alice'**  
Show the configuration the user had, without restoring it.

**otpme-trash del 1774709126.6068273-a48eb24e-4238-4b40-b5b8-e4b863a43d7c**  
Remove that entry for good.

**otpme-trash empty**  
Remove every entry you may remove, for good.

# FILES

*/var/lib/otpme/trash/*  
One directory per entry, named by its trash ID, on every node of the
site. In it one file per object, named by its OID with **+** for **/**,
and *.deleted_by* with the token that deleted it.

# SEE ALSO

**otpme**(1), **otpme**(7)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
