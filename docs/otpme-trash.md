# NAME

otpme-trash - manage the OTPme trash

# SYNOPSIS

**otpme-trash** *command* \[*options*\]

# DESCRIPTION

**otpme-trash** manages the OTPme trash. Deleted objects are moved to
the trash and can be restored or permanently removed.

# COMMANDS

**show \[**--fields** *field1,field2,...*\] \[**-z** *size_limit*\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\]**  
Show trash contents.

**restore \[**--keep**\] \[**--objects** *oid1,oid2,...*\] *trash_id***  
Restore object(s) from trash.

**del *trash_id***  
Permanently delete an entry from trash.

**empty**  
Empty the entire trash.

# OPTIONS

**--fields *field1,field2,...***  
Select output fields.

**-z *size_limit***  
Limit output size.

**--raw**  
Show raw output without header.

**--csv**  
Output in CSV format.

**--csv-sep *sep***  
CSV separator character.

**--keep**  
Keep a copy of the object in trash after restoring.

**--objects *oid1,oid2,...***  
Restore specific objects from a trash entry.

Global options are available for all commands. See **otpme**(1) for
details.

# EXAMPLES

**otpme-trash show**  
List all objects in the trash.

**otpme-trash restore 1774709126.6068273-a48eb24e-4238-4b40-b5b8-e4b863a43d7c**  
Restore a trash entry by its trash object ID.

**otpme-trash restore --keep 1774709126.6068273-a48eb24e-4238-4b40-b5b8-e4b863a43d7c**  
Restore a trash entry, keeping a copy in trash.

**otpme-trash del 1774709126.6068273-a48eb24e-4238-4b40-b5b8-e4b863a43d7c**  
Permanently remove a trash entry.

**otpme-trash empty**  
Empty the entire trash.

# SEE ALSO

**otpme**(1), **otpme**(7)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
