# NAME

otpme-shell - get a shell on a host

# SYNOPSIS

**otpme-shell** \[*options*\] *host*

# DESCRIPTION

**otpme-shell** gives you a shell on a host of your realm. You do not
need to reach the host over the network, and the host does not need an
open SSH port. The host connects out to the master node of its site, and
your shell goes through that node.

This is for a host you cannot reach otherwise. A machine behind NAT, a
machine in a customer network, a machine whose sshd is broken.

What happens when you run it:

1.  A **remote_access** job is created for the host and signed with your
    sign key. It is a configuration job like any other, see
    **otpme-deploy**(1).

2.  The host hears about the job and connects out to the master node of
    its site.

3.  You connect out to the same node. Both sides meet there under the
    UUID of the job.

4.  The host and your terminal speak SSH to each other through that
    node.

The node only moves bytes. It cannot read the session.

## What you need

You must be logged in:

> **otpme-tool login *user***

The job is signed with your sign key, so a shell is always asked for by
somebody.

You need an SSH agent with a key in it. The agent is the same one you
use for **ssh**(1).

The host must trust you for this job type. Add the signer on the host
once:

> **otpme-tool add_signer --signer-type remote_access
> 'user\|example.org/alice'**

You must also be allowed to create jobs for the host. This is set with
the config parameter **allow_confd_jobs**.

A **remote_access** signer may ask for a shell, and gets in with the key
of an SSH token that may log in to this host as the user the shell runs
as: the keys OTPme hands to sshd, see **FILES**. A key in
*\~/.ssh/authorized_keys* does not count. A signer that may bring its
own key (**--allow-throwaway-key**) needs nothing but its signature, and
gets any shell, root included. Give that one only to whom you trust with
root access. See **otpme-tool**(1) for signers.

## Which key gets you in

Your SSH agent offers its keys and the host takes the first one it
allows. The host allows the keys of the **authorized_keys** file OTPme
keeps for the user the shell runs as, see **FILES**. Those are the same
keys **otpme-get-authorized-keys** hands to sshd. A key in
*\~/.ssh/authorized_keys* does not count.

So nothing has to be set up for a session. The key you log into the host
with is the key you get a shell with. A key taken away from a user is
taken away here with it.

With **--user** the keys of that user are used, not root's.

A key is not used if its **authorized_keys** line limits what the key
may do. **command=** means the key is not for a shell. **from=** means
not from here, and a session through a node does not come from where you
are. **no-pty**, **restrict** and the others each say something this
does not do. Only **environment=** is fine: it says what the key is, not
what it may do. Such a key is skipped and the job log says so.

## A key the job brings along

With **--throwaway-key** a new key pair is made for this one session.
The job carries its public half, and then the host allows that key and
no other. The private half exists for the minutes the job lives and is
written nowhere.

This way in is weaker, and not because the key is new. It is weaker
because it needs one thing where the ordinary way needs two.

The ordinary way needs the signature of the job **and** a key in the
**authorized_keys** OTPme keeps for the user on the host. Take either
away and the door is shut. A job that brings its own key needs only the
signature: it names the key it will be entered with, so whoever can sign
such a job for the host has a shell.

So the host says who may ask for it, and it says so per signer. On the
host, as root:

> **otpme-tool add_signer --signer-type remote_access
> --allow-throwaway-key 'user\|example.org/alice'**

Or with a job, which needs a **signer_mgmt** signer, and such a signer
can do anything to the host anyway:

> **otpme-deploy add --host client1 --arg type=remote_access --arg
> 'signer=user\|example.org/alice' --arg allow_throwaway_key=yes
> signer_mgmt add_signer**

Without it the host refuses the job and says so. That is a refusal and
not a failure: the job stays, and the host takes it up again when its
signers change. **otpme-shell** waits for the host only two minutes and
then takes the request back, so ask again once the signer has the
permission.

**otpme-tool show_signer** has a column for it, so you can see which
signers may. Use **--throwaway-key** when you have no agent, or when you
want a shell that no stored key can open.

## How the host is checked

A node brings two sides together. Nothing stops a node from bringing the
wrong ones together.

So the host signs a line that says which SSH host key it is about to
use. It signs with the key it joined the realm with. **otpme-shell**
checks that line against what the tree says about the host you asked
for. This happens before a word of SSH is spoken.

If it does not match, nothing is sent and you get an error.

That alone says which key the session is with, not that the key belongs
to the host that named it. A host may name any key, including one of a
third host, and then pass the session through to that host: everything
above still holds, and you are working on a machine you never asked for.

So once the session stands, the host signs the identity of that session
as well, again with the key it joined the realm with. Only the two ends
of a session can work that identity out — it is the hash of their key
exchange, and the shared secret of that exchange is part of it. A host
that only passes the session on never learns it and has nothing to send.

Both checks have to pass before the shell starts.

This is what **known_hosts** does for **ssh**(1), with the realm in
place of a file: there is no first connection you have to trust, and no
warning when a host is reinstalled.

Both checks rest on the key the host was joined with, read from this
host's copy of the tree — so whoever can change the tree can change
which key a session is checked against. Set **PIN_HOST_KEYS** (see
**otpme.conf**(5)) and they cannot change it here: the key of a host is
written down on the first sync that brings it, and one that differs does
not replace it. A session to that host does not open until you take the
new key over with **otpme-tool update_host_keys** as root, which shows
you what changed.

On a host, a session to another host needs **PIN_HOST_KEYS**. Without it
a host gets only its own host object, so it has no key for any other
host. A session to a node works either way.

## How long it lasts

**--expiry** says how long the request stays good. Default is 5 minutes,
the host allows at most 1 hour. It is the time in which the host has to
pick the job up. It is not the length of the session.

A session lasts as long as you work in it. There is no limit, and no
limit on how much data goes through it.

Both sides ask each other every 30 seconds whether the other is still
there. A session whose far end is gone ends in minutes instead of
hanging.

## More than one at a time

A host runs one configuration job at a time. A shell is the exception:
it runs beside other jobs, and other jobs run beside it. A host carries
up to 8 sessions at the same time.

So two people can have a shell on the same host, and a package can be
installed while somebody is logged in.

## Which node you meet at

Both sides meet at the master node of the site of the host. They reach
it over the management address of that site, which is the floating IP of
its master.

The daemon that brings them together is **racd**, on port 2031. It runs
on the master node and nowhere else: it is started when a node takes the
master role and stopped when it loses it. Both sides need to reach that
address.

There is nothing to choose here, so there is no option for it.

## A host in another site

Name the site with the global option **-s**:

> **otpme-shell -s *site* host**

That one option moves the whole command to that site. The job is made by
the management daemon there, because that is where the connection goes,
and only the nodes of a site hand a job to a host of that site. The host
is looked up there as well, and both sides meet at the master of that
site.

Nothing else changes. The job is signed with your key here, and the host
holds the signature against the signers it has — so the host needs a
signer for you (**otpme-tool add_signer**), the same as a host of your
own site. The two sides show each other a certificate, and those are
good across the realm: a host trusts the CA of the realm and the CA of
every site in it.

Without **-s** the command works against your own site, so a host of
another site is not found there.

An open session holds the master failover off while it lasts. So a shell
that is left open overnight keeps the master role where it is.

# OPTIONS

**--user *user***  
Run the shell as this user. Default is **root**. The user must exist on
the host.  
Lower case, up to 32 characters, starting with a letter or **\_**, and
it may hold digits, **\_**, **-** and **.**, for example
**firstname.lastname**.

**--command *command***  
Run this instead of a shell. The host runs this and nothing else,
whatever the client asks for.

**--expiry *time***  
How long the request stays good, for example **30s**, **5m** or **1h**.
Default **5m**, at most **1h**.

**--throwaway-key**  
Make a new key for this session instead of using the SSH agent.  
The host allows this only for a signer that was given the permission by
hand. See **A key the job brings along**.

## Giving up on it

Press Ctrl+C while you wait for the host. It works from the moment you
asked for the shell until the session is up.

Once the session is up, Ctrl+C belongs to the shell at the other end,
the same as in **ssh**(1).

Giving up takes the request back, and so does a session that never came
about: a host that has not picked it up yet does not open one for it any
more. Where taking it back fails, you are told so: then it stands until
it expires, and **otpme-deploy cancel** with its UUID takes it back by
hand.

# EXIT STATUS

**otpme-shell** exits with the exit status of the shell or of the
command.

It exits with **255** when the connection failed and not the command: no
session came about, or it was lost. This is what **ssh**(1) does, so a
script around it reads the two apart the same way.

It exits with **130** when you gave up with Ctrl+C. That is 128 plus the
signal, the way a shell reports an interrupted command.

At the end you are told what happened, the way ssh says it:

> Connection to *host* closed.

> Connection to *host* closed by remote host: *reason*

# EXAMPLES

**otpme-shell client1**  
A root shell on client1.

**otpme-shell --user alice client1**  
A shell as alice. Uses the keys of alice on that host.

**otpme-shell -s munich client2**  
A root shell on **client2**, which is a host of site **munich**.

**otpme-shell --command 'systemctl status otpme' client1**  
Run one command and print what it says.

**otpme-shell --throwaway-key --expiry 30s client1**  
A shell on a key made for this session, and a request that is good for
30 seconds. Needs a signer with **--allow-throwaway-key** on that host.

**otpme-tool add_signer --signer-type remote_access 'user\|example.org/alice'**  
On the host, once: let alice ask for shells there. She gets in with the
key of an SSH token that may log in as that user, see **otpme-tool**(1).

**otpme-tool show_signer --signer-type remote_access**  
On the host: which signers may ask for a shell, and which of them may
bring their own key.

**otpme-deploy results *job_uuid***  
What came of a session. Says who got in, how the session ended and which
keys were skipped.

# FILES

*/var/cache/otpme/ssh/authorized_keys/\<user\>/authorized_keys*  
The keys the host allows, on the host. Written by **hostd** from the SSH
tokens of the realm.

*/var/log/otpme/confd/\<job_uuid\>.log*  
The log of one session, on the host. Never what was said in the session.

# NOTES

A session is written into the login history of the host, so **last**(1)
there shows it like any other login:

>     root  pts/3  otpme/edfc63d5  Thu Oct  8 15:53  still logged in

The origin names the job, and the job names the rest: who asked for the
shell, which key got in and when it was signed (**otpme-deploy show
***uuid*).

While it runs **last** says **still logged in**, because the record
names the process of the shell and that one is still there. A session
whose end was never written — one that was cut off hard — shows as
**gone - no logout**.

The shell is a login session of that user for the kernel as well, the
same as a login over **ssh**(1). So the audit of the host puts what
happens in the session under the user the shell runs as, and not under
the daemon that started it.

It is not in **who**(1). That reads another file, one in which a record
has to be found and replaced rather than appended, and which every other
login on the host writes too.

The size of your terminal is sent when the shell starts, and again
whenever you resize the window.

Your language is offered to the shell (**LANG** and the **LC\_\***
variables). Nothing else from your environment is sent. A shell that ran
with the environment of whoever asked for it would run their code.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-deploy**(1), **otpme-tool**(1),
**otpme-host**(1), **otpme-node**(1), **ssh**(1), **last**(1),
**who**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
