# NAME

otpme-mount - mount and unmount OTPme file shares

# SYNOPSIS

**otpme-mount** \[*options*\] *share* \[*mountpoint*\]  
**otpme-mount -a**  
**otpme-mount -u** *share*  
**otpme-mount -a -u**  
**otpme-mount --list**

# DESCRIPTION

**otpme-mount** mounts a file share of your realm with FUSE. The share
lives on the nodes, the mount runs on your computer, and every request
goes to a node over the network. See **otpme-share**(1) for the shares
themselves.

You must be logged in:

> **otpme-tool login *user***

A share is mounted with your token, so the mount shows what that token
may see.

## Which share

A share has an ID, and that is what this command takes:

> *\<realm\>/\<site\>/\<share\>*

The realm is part of it because two realms may have a site of the same
name. Leave it out and write *\<site\>/\<share\>*; then it is a share of
your own realm.

## Where it is mounted

Give a mountpoint and the share is mounted there.

Leave it out and **otpme-agent** mounts the share at the usual place:

> */otpme/\<user\>/\<realm\>/\<site\>/\<share\>*

The first part is the mount root (**MOUNT_ROOT_DIR**, see
**otpme.conf**(5)). The directories are made as needed and belong to
you.

This is also where the shares of a user are mounted at login. A mount
made by hand with a mountpoint of your own is yours alone: the agent
does not know about it, so it is not unmounted with the others.

## Which node

By default the nodes of the share are asked for, and one of them is
picked at random. That spreads the load. When a node cannot be reached
the next one is tried.

With **--nodes** you say which nodes to use instead.

## A node that goes away

A share is a network filesystem, and a node can go away while the share
is mounted. Then every request fails right away, so a program sees an
error instead of hanging.

With **--hard** a write waits instead. It waits until a node answers
again, however long that takes, which keeps a program from losing data
it has already handed over. Everything else still fails right away.

## Encrypted shares

The data of an encrypted share is encrypted on your computer, with a key
the share keeps for your token. The key never reaches the node in clear.

Two things follow from that. The key is handed to you when the share is
mounted and is decrypted with the encrypt key of your user, so with
**yubikey_piv** the token has to be plugged in. And the key is held
against the share before a single request is served: the share keeps a
value that only its own key reads. A mount with another key is turned
away, instead of writing data that nobody can read afterwards.

A share made before that value existed gets one from the first mount
whose key reads one of the names in it. Where no name reads, the mount
is turned away as well: either the key is the wrong one, or the share
holds data that was written with a wrong one. Files in the share root
that this filesystem did not write — a **lost+found**, something the
admin put there — say nothing either way and are left out of it.

**--master-password-mount** asks for the master password of the share
instead and makes the key from it. Only a master password token may do
this (see **otpme-share**(1)). It is the way in when no token of yours
holds a key for the share.

**--add-share-key** stores the key that was made from the master
password for your own token, so later mounts need no master password. It
needs **--master-password-mount**, and therefore a token that may use
the master password of the share.

It also has to run in the login session of the system user **root**.
That is the session and not the command: the user is read from the
agent, so a **sudo** in front of this command does not make one. Log in
as root and run it there:

> **otpme-tool login *user***  
> **otpme-mount --master-password-mount --add-share-key *share*
> mountpoint**

This is also how a share is taken over whose data is older than its
share object, see **--no-key-gen** in **otpme-share**(1).

# OPTIONS

**-a**  
Mount all shares you may mount, each at the usual place. Not for a
mountpoint of your own, and not together with **--foreground**,
**--master-password-mount** or **--add-share-key**.

**-u**  
Unmount the share. With **-a** it unmounts all of them. The agent does
the unmounting, so this reaches the mounts it made — the ones at the
usual place. A mount with a mountpoint of your own is not one of them;
unmount that one with **fusermount**(1).

**--list**  
List the shares you may mount.

**--nodes *node1,node2***  
Use these nodes instead of the ones the share names.

**--hard**  
Let a write wait while no node can be reached, instead of failing. See
**A node that goes away**.

**--encrypted**  
Say that the share is encrypted. Only needed when a mountpoint and
**--nodes** are both given: then nothing is asked of the management
daemon, and this is the only way it is known.

**--master-password-mount**  
Make the key of an encrypted share from its master password. You are
asked for the password.

**--add-share-key**  
Store the key made from the master password for your own token. Needs
**--master-password-mount**, and the login session of the system user
**root**. See **Encrypted shares**.

**--foreground**  
Keep the mount in this process instead of leaving it behind in one of
its own. The command ends when the share is unmounted. Useful for
looking at what a mount does.

# EXAMPLES

**otpme-mount berlin/projects**  
Mount the share *projects* of site *berlin* at
*/otpme/\<user\>/\<realm\>/berlin/projects*.

**otpme-mount example.org/berlin/projects /mnt/projects**  
Mount it at */mnt/projects*, with the realm written out.

**otpme-mount -a**  
Mount every share you may mount.

**otpme-mount -u berlin/projects**  
Unmount that share.

**otpme-mount -a -u**  
Unmount all shares.

**otpme-mount --list**  
Which shares are there for you.

**otpme-mount --hard berlin/vmail /mnt/vmail**  
Mount with writes that wait for a node instead of failing.

**otpme-mount --master-password-mount berlin/secure /mnt/secure**  
Mount an encrypted share with its master password.

**otpme-mount --master-password-mount --add-share-key berlin/secure /mnt/secure**  
The same, and keep the key for your own token, so the next mount needs
no master password. Runs in the login session of root.

# NOTES

An unencrypted share connects in the background and answers with
**ENOENT** until the connection stands. So a program that looks at the
mountpoint in the first moment is told the path is not there, instead of
waiting for it. An encrypted share waits instead: getting its key may
ask for a password, and that needs a command that waits for the answer.

A share can drop its connection when nothing uses it for a while, and
with it the share key (**mount_timeout**, see **otpme-share**(1)). The
next request connects again. For an encrypted share that means the key
is asked for again, so a token that has to be plugged in has to be
plugged in again.

A node asks once a second whether your token may still use the share,
and stops serving the mount when it may not. Taking a permission away
also tells the hosts to unmount the share, see **--share-notify** in
**otpme-share**(1).

After a mount that went to the background, the readahead of the
mountpoint is set with **sudo -n setreadahead** *mountpoint*. Without
that sudo rule the mount still works, only slower on large reads.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-share**(1), **otpme-tool**(1),
**otpme.conf**(5)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
