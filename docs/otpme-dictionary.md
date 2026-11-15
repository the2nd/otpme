# NAME

otpme-dictionary - the word lists a password policy checks passwords
against

# SYNOPSIS

**otpme-dictionary** *command* \[*options*\] \[*dictionary*\]

# DESCRIPTION

**otpme-dictionary** manages dictionaries: lists of words that make a
password easy to guess.

A password policy with the strength checker **spsc** looks the parts of
a password up in the dictionaries of its **dict_order**, see
**otpme-policy**(1). A part it finds counts as guessed with as many
tries as the dictionary says, and the password gets a lower score. The
first dictionary in **dict_order** that has the part counts. A
dictionary that is in no **dict_order** does nothing.

A dictionary belongs to a site, and a policy uses only those of its own
site. Every site comes with a set of them, see **FILES**.

There are three types of dictionary; the type is chosen with **add** and
cannot be changed:

> -   **list**: words in no order. A word found in it counts as one of
>     10000 tries, however long the list is.
>
> -   **sorted-list**: words in the order of how often they are used,
>     the most common first. A word found in it counts as many tries as
>     its place in the list, so the first word is the weakest. Capital
>     letters raise the count: two to five times for a common spelling
>     like **Berlin** or **BERLIN**, far more for an odd one like
>     **bErLin**.
>
> -   **guessing**: no words, but the pieces of three characters that
>     words begin, go on and end with, learned from a file of words with
>     **word_learning**. A part of the password that is made of letters
>     only, and begins, goes on and ends like those words, counts as a
>     word even when no list has it. It counts as many tries as the
>     dictionary has entries.

# COMMANDS

## Dictionary Management

**add *dictionary* \[*dict_type*\]**  
Add an empty dictionary; **word_import** or **word_learning** fill it.
*dict_type* is **list** (the default), **sorted-list** or **guessing**,
see **DESCRIPTION**.  
With a path, e.g. **wordlists/german**, it goes into that unit; else
into the unit a **defaultunits** policy names, or into
**dictionaries**.  
Needs **add:dictionary** on the unit.

**del \[**--no-trash**\] *dictionary***  
Delete the dictionary. It goes to the trash, see **otpme-trash**(1);
**--no-trash** deletes it right away.  
A password policy that names it skips it from then on, and
**remove_orphans** of the policy takes it off the list.  
Needs **delete:object** on the dictionary or **delete:dictionary** on
the unit.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*dictionary*\]**  
Without a dictionary: a table of them, with their unit, type, status,
size, policies, ACL inheritance and description. The size is the memory
its words take.

**-a**  
Also the dictionaries you may only look at, not just the ones you may
change.

**-z *N***  
How many dictionaries to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named.

**--limit *N*, **--policy-limit** *N***  
How many policies to print per dictionary.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
**--raw** leaves the header and the borders out, **--csv** prints one
row per line with **;** between the columns, and **--csv-sep** uses
another separator.

A column you may not see says **-**. With a dictionary named, this
prints the object itself instead of a table row, one value per line, its
type and size among them.

**show_oid \[**--full**\] *dictionary***  
Show the OID of the dictionary:
**dictionary\|\<realm\>/\<site\>/\<name\>**. With **--full** the full
OID, which names the unit as well:
**dictionary\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *dictionary***  
Show the UUID of the dictionary.  
Needs the ACL **view_public:object**.

**list \[**-a**\] \[**--attribute** *attribute*\] \[*pattern*\]**  
List the dictionary names, and with a pattern only those that match it,
see **SELECTING OBJECTS** in **otpme**(1). You get the dictionaries you
may change; **-a** adds those you may only look at. **--attribute**
matches the pattern against that attribute instead of the name.

**enable *dictionary***  
**disable *dictionary***  
A password policy checks only against enabled dictionaries; a disabled
one stays on its list and is skipped.  
Needs **enable:object** or **disable:object**.

**rename *dictionary* *new_name***  
Rename the dictionary. A password policy knows it by its UUID, so it
keeps it.  
Needs **rename**.

**move \[**--keep-acls**\] *dictionary* *unit***  
Move the dictionary into another unit of the same site. It keeps its
ACLs; where ACL inheritance is on for it, the default ACLs of the old
unit are taken away and those of the new one given. **--keep-acls**
keeps all ACLs as they are.  
Needs **move** on the dictionary and **add:dictionary** on the unit.

**touch *dictionary***  
Write the index entries of the dictionary again.  
Needs **touch**.

**auto_disable *dictionary* *time***  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). A relative time counts from when it is set, and again from
when the dictionary is enabled. **0** removes it. It is refused for a
dictionary OTPme comes with, e.g. **german**; a time set on one before
does nothing.  
Needs **edit:auto_disable**.

## Word Management

The file is read on your side, also as *.gz*, and only its entries go to
the node. New entries go after those the dictionary has; one it has
already is skipped. To replace them, **clear** first. The commands that
change something ask first; the global option **-f** skips the question.

**word_import *dictionary* *file***  
Add the words of *file* to a dictionary of type **list** or
**sorted-list**.  
The first word of each line is taken, in small letters, if it has 3
characters at least. The words keep the order of the file, and for a
**sorted-list** that is their rank: the first line is the most common
word. A dictionary of type **guessing** is refused.  
Needs the ACL **add:words**.

**word_learning *dictionary* *file***  
Build the entries of a dictionary of type **guessing** from the words of
*file*, those with 4 characters at least.  
Every word is cut into pieces of three characters: its start (**abc:**),
the pieces in its middle (**:abc:**) and its end (**:abc**). A piece
that comes 3 times at least is kept, the most common first. Every three
letters that come in no middle at all are kept as well, as **-abc-**. A
dictionary of another type is refused.  
Needs the ACL **add:words**.

**word_export *dictionary***  
The entries of the dictionary to stdout, one per line, in their order.  
Needs the ACL **dump**.

**clear *dictionary***  
Remove all entries of the dictionary.  
Needs the ACL **delete:words**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. The first entry is the one of **add**. A change can carry a
comment of its own, through the global option **--changelog**.

Nothing is written where the **changelog** config parameter is off. It
is read along the cascade (dictionary, unit, site). Without any value
anywhere it is on.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *dictionary***  
Show the changelog of the dictionary, one entry per line: its
*entry_id*, the time, who made the change and what was done, then a
detail in round brackets and the comment in square brackets where there
are any. Needs the ACL **view:changelog**.

**edit_changelog *dictionary* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. That writes an
entry of its own. Needs the ACL **edit:changelog**.

**del_changelog *dictionary* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. That writes an entry of its own. Needs the
ACL **edit:changelog**.

**clear_changelog *dictionary***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the object counts, read along its cascade.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the dictionary. Which policies there are, and what each of them
does, is in **otpme-policy**(1).

Two policy types fit a dictionary:

-   **authonaction** asks for a login again before the actions of the
    dictionary, see **AUTH ON ACTION HOOKS**.

-   **autodisable** disables the dictionary after a while. A password
    policy skips a disabled dictionary: passwords are no longer checked
    against it. It is refused for the dictionaries a site comes with.
    One set with **auto_disable -u** (unused for) is refused too: a
    dictionary does not keep its last use.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *dictionary* *policy***  
Attach a policy to the dictionary.  
A policy has a list of object types it is for; one that does not name
**dictionary** is refused. So is a second policy of a type that allows
only one per object, even when the first one is disabled, and a policy
the dictionary already has.  
Needs the ACL **assign:policy**.

**remove_policy *dictionary* *policy***  
Remove a policy from the dictionary.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *dictionary***  
List the policies attached to the dictionary, the disabled ones too,
marked **(disabled)**. Use **--return-type** to select the attribute
returned (**name**, **read_oid**, **full_oid**, **uuid**); without it
the names. Only the names are marked. Use **--policy-types** to list
only policies of the given types; these are policy types, not policy
names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this dictionary. The somebody is a
role or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean is under
**ACLs** in **otpme**(7). Tab completion after **add_acl** offers the
ACLs a dictionary knows. A dictionary has no default ACLs, **+acl** and
**++acl**: nothing lies in a dictionary that could get them.

Adding and removing ask first; the global option **-f** skips the
question.

**add_acl *dictionary* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this dictionary.  
*owner_type* is **role** or **token**. *owner* names it the way
**list_acls** prints it: a role as *site/name*, or by its name alone on
its own site; a token as *user/token*. An ACL can carry a value, for
example **add:words**. To give several ACLs at once, separate them with
commas: **add:words,delete:words**.  
Needs the ACL **add:acl**.

**del_acl *dictionary* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/helpdesk:add:words**.  
Needs the ACL **delete:acl**.

**list_acls *dictionary***  
Show the ACLs that lie on this dictionary, i.e. who may do what with
it.  
Needs the ACL **view:acl**.

**enable_acl_inheritance *dictionary***  
Let a move of the dictionary swap its default ACLs: what the old unit
handed down is taken away, and what the new unit hands down is given. It
does not by default; a move then leaves the ACLs of the dictionary as
they are.

Only a move asks this. A new dictionary gets the default ACLs of its
unit, and **add_acl -a** or **-r** on a unit reach it either way. A move
with **--keep-acls** leaves its ACLs alone all the same.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the dictionary leaves its ACLs alone as well, and says so. Otherwise
moving an object into a unit would be a way of handing yourself the
default ACLs of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *dictionary***  
A move leaves the ACLs of the dictionary as they are again.  
Needs the ACL **disable:acl_inheritance**.

## Configuration

A dictionary has two config parameters: **changelog** and
**allow_changelog_clearing**, see **Object Changelog** above and
**otpme**(7). A parameter is looked up at the dictionary, then at its
unit and the units above it, then at the site.

**config \[**-d**\] \[**-a**\] *dictionary* *parameter* \[*value*\]**  
Set a parameter on the dictionary.

**-d**  
Remove the parameter from the dictionary, or with a value only that one
value from a list. It is not set back to a default: what applies
afterwards is what the units or the site say.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

The ACL is per parameter, **set:config:\<parameter\>**.

**show_config *dictionary* \[*parameter*\]**  
The parameters set on the dictionary itself, or only the one named.
Nothing is shown for a parameter that the dictionary gets from a unit or
from the site.

**get_config *dictionary* *parameter***  
What the parameter comes to for the dictionary, once the dictionary, its
units and the site have been looked at. So this answers what applies,
where **show_config** answers what was set here.

**description *dictionary* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing. Needs **edit:description**.

**info \[**--language** *LANG*\] *dictionary* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable. Needs
**edit:info**.  
Without **--language** the text is the administrator's own note. Nothing
shows the info of a dictionary to a user, so a text for a language stays
a note as well.

**dump_info \[**--language** *LANG*\] *dictionary***  
Write one of those texts to stdout. **--language** picks which one;
without it you get the note of the administrator. Needs **view:info**.

## Export and Cleanup

**export \[**--password** *password*\] *dictionary***  
Write the whole object of the dictionary to stdout, as JSON: its type,
its entries (compressed), ACLs, policies, config parameters and the
rest. **otpme-tool import** reads it back.  
A dictionary holds no key and no secret, so **--password** has nothing
to encrypt: the output is in clear either way. **word_export** is the
command for the entries alone.  
Needs the ACL **export**.

**remove_orphans *dictionary***  
Remove references to objects that are gone: orphan ACLs and policies of
the dictionary.  
It asks once for what it found; the global option **-f** skips the
question.  
Needs the ACL **remove:orphans**.

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# EXAMPLES

## Words of your own

**otpme-dictionary add products**  
**otpme-dictionary word_import products products.txt**  
A dictionary of type **list** with the product names of the company, one
per line in *products.txt*. It goes into the unit **dictionaries**.

**otpme-policy --type password strength_checker_opts password_strength "min_score=2;dict_order=products,common-passwords,german,english"**  
The password policy of the site looks the passwords up in it, before the
others. Each call replaces all options of the checker, so name every
dictionary that should still be used.

## Replacing the words

**otpme-dictionary clear products**  
**otpme-dictionary word_import products products.txt**  
**word_import** only adds; to drop the old words, clear first.

## A guessing dictionary

**otpme-dictionary add products-guessing guessing**  
**otpme-dictionary word_learning products-guessing products.txt**  
The pieces of three characters the product names are made of.

## Looking at a dictionary

**otpme-dictionary show german**  
Its type, its size and the rest.

**otpme-dictionary word_export german \| head**  
Its first entries.

## Not using a dictionary for a while

**otpme-dictionary disable abbreviations-it**  
The password policy skips it until it is enabled again, without changing
its **dict_order**.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A dictionary has
the hooks every object type has, and these; a command of another name is
in brackets:

> add_words (word_import), dump.

# FILES

*/var/lib/otpme/tree/*  
The objects of the realm, on the nodes and, by sync, on the hosts. A
dictionary is the directory *\<name\>.dictionary* in the directory of
its unit, e.g.
*\<realm\>.realm/\<site\>.site/dictionaries.unit/german.dictionary/*.
Its entries are in *object.json*, with the rest of its settings. Change
them with the commands above, not in the file.

*/etc/otpme/dicts/\<name\>.gz*  
The words of the dictionaries a site comes with. A file is read once,
when the site adds its dictionary; changing the file later does not
change the dictionary.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-policy**(1), **otpme-unit**(1),
**otpme-trash**(1), **otpme-tool**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
