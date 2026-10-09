# NAME

otpme-deploy - manage configuration jobs for hosts

# SYNOPSIS

**otpme-deploy** *command* \[*options*\]

# DESCRIPTION

**otpme-deploy** creates configuration jobs for hosts and shows their
results. A job does one thing on one or more hosts, for example install
a package, add an apt repository or restart a service.

Every job is signed with the sign key of the user who creates it. Before
you sign, OTPme shows you what the job does. The host checks the
signature before it runs the job.

Two checks must pass before a job runs:

1.  The nodes check that you may create jobs for the host. This is set
    with the config parameter **allow_confd_jobs**.

2.  The host checks that the job is signed by a signer it trusts for
    this job type. Signers are added on the host with **otpme-tool
    add_signer --signer-type** *job_type*.

A host without a signer for the job type refuses the job and says so. A
refusal is not a run: the job is still there, and it runs as soon as the
reason is gone. Add the missing signer and the host does the job, you do
not need a new one. See **Refused jobs**.

You name the hosts of a job with **--host**, **--unit**, **--role** or
**--group**. To find out which hosts need the job, ask
**otpme-inventory**(1): it knows which host has which package version,
and what each machine is made of. See **Finding the hosts** under
**EXAMPLES**.

## Who can see and change jobs

Admins can see and change all jobs. Other users see a job if they may
create jobs for at least one of its hosts. They only see the state and
the results of those hosts. The user who created a job sees all of its
hosts.

**ack** and **cancel** change the whole job. They are allowed for the
user who created the job, and for users who may create jobs for all of
its hosts.

## Hosts in another site

A job is made by the management daemon the command goes to, and only the
nodes of that site hand it to a host. So a job for a host of another
site is made in that site, with the global option **-s**:

> **otpme-deploy add -s *site* --host *host* type action**

The same **-s** is needed for every command about that job — **list**,
**show**, **results**, **ack** and **cancel** — because the job is there
and nowhere else.

Nothing else changes. The job is signed with your key, and the host
holds the signature against the signers it has, so it needs a signer for
you like a host of your own site does.

## How jobs run

On every host, the **confd** daemon asks the nodes of its site for new
jobs every 60 seconds. It runs one job at a time. A **remote_access**
job is the exception. It is a shell for a user, not work on the host. So
it runs beside other jobs, and other jobs run beside it. A host runs up
to 8 sessions at the same time.

Each job runs as its own transient systemd service
(**otpme-confd-job-***uuid***.service**). This way a job keeps running
when OTPme is restarted, even if the job restarts OTPme itself.

A job runs only once on each host. If the result can not be sent, confd
sends it again later. It does not run the job again.

The full output of a job stays on the host in
*/var/log/otpme/confd/uuid.log*. The nodes get the last 64 KiB of the
output.

## Refused jobs

A host refuses a job it may not or cannot run. It may not run a job it
holds no signer for, one whose signature does not hold, or one that
would take away its last **signer_mgmt** signer. It cannot run a job
that names an object it has not synced yet.

A refused job is not done. Nothing ran, and the job can still run later,
so the host does not put it away. It reports the refusal once, so you
see why nothing happened, and it keeps the job in view.

When the host may not run a job, it waits for its signers to change. Add
the signer it was missing, and the job runs with the next round.

When the host cannot run a job, it asks for the job again every round.
Nothing tells a host that a user or a role has arrived, so it tries
until it can. This needs nothing from you: the sync brings the object,
and the next round runs the job.

A failed job is done. It ran, and it did not work. It is never run
again, on that host you need a new job.

**cancel** ends the waiting. A job that was taken back is not offered to
a host anymore, so a host that refused it never sees it again. The
refusal it reported stays, and **show** names it next to the
cancellation: the host saw the job and said no, and then the job was
withdrawn.

**show** and **results** name both states, and **ack** takes both.

## How long jobs are kept

Jobs and their results stay on the nodes for 90 days (site parameter
**conf_job_max_age**). This also applies to jobs that worked, so you can
see which jobs were already sent.

A job with something unanswered about it stays until you acknowledge it
with **ack**, however old it is. After that it is removed when it is
older than **conf_job_max_age**.

Unanswered is a host where the job failed, a host that refused it, and a
host that never reported at all. The last one is what nothing else would
tell you about: a host that was switched off for three months is still
waiting for that job, and the job waits with it.

Two kinds of job are not kept that way.

One you took back with **cancel**: you looked at it when you did that,
and the hosts that never ran it were never meant to. That answers the
whole job, a host where it failed before you took it back included —
what that host did is in its result either way, and a job that shows as
over must not be the one line that is still waiting for somebody.

And a **remote_access** job, which is a shell somebody was waiting for.
**otpme-shell** stands there until the host comes and says what came of
it, so there is nothing to find out later — and a job is made for every
shell, so held like the others they would pile up.

Such a job is not kept for 90 days either. It is removed an hour after
it expired, which is the site parameter **remote_access_job_max_age**;
counted from the expiry, because that is when the shell stopped being
anybody's business. Set it to **0** to have them go as soon as they
expire.

For every other job type an expired job is not an exception. Every job
has an **--expiry** and the default is 30 days, which is less than the
90 a job is kept — so by the time anything looks at an old job it has
expired, and that says nothing about whether anybody saw it.

**otpme-deploy list --pending** shows what is still waiting for a host.

If a host is deleted before it ran a job, the job does not wait for it.
The host is shown as deleted.

On the host, confd keeps the job logs for 90 days.

# JOB TYPES

Each job has a job type and an action. The job type is also the signer
type the host checks against. Arguments are given with **--arg**
*name***=***value*. A value with commas is a list.

**sw_mgmt**  
Manage software packages.

**install packages=*pkg1,pkg2***  
Install packages.

**remove packages=*pkg1,pkg2* \[**autoremove=yes**\]**  
Remove packages. With **autoremove=yes**, packages that are no longer
needed are removed too.

**upgrade packages=*pkg1,pkg2***  
Upgrade installed packages.

**dist_upgrade**  
Update the package lists, then upgrade every package. Stops if the
update fails.

**autoremove**  
Remove packages that are no longer needed.

**repo_mgmt**  
Manage apt repositories.

**add_repo name=*name* line=*line* **--key** *key_file***  
Add a repository and its signing key, then update the package lists.
*line* is a normal sources.list line without options, for example **"deb
https://repo.example.org/debian bookworm main"**. The key is required.

**del_repo name=*name***  
Remove a repository that was added with **add_repo**, then update the
package lists.

**update**  
Update the package lists.

**signer_mgmt**  
Manage the signers of the host.

**show_signer \[**type=***signer_type*\]**  
Show the signers the host holds, or only those of one type. The answer
is the output of the job, so **otpme-deploy results** shows it. This
action changes nothing.

**add_signer type=*signer_type* signer=*object_id* \[**tags=***tag1,tag2*\] \[**verify_token_opts=***yes*\] \[**allow_throwaway_key=***yes*\]**  
Add a system-wide signer. *object_id* is the OID of a user or role, for
example **role\|example.org/berlin/sw-admins**. The signer is pinned to
the current key of the user or role. If the signer exists already,
nothing changes.

**verify_token_opts** (default yes) requires the signature of an SSH
token to cover the key options the key is used with, for example
**command=**.

**allow_throwaway_key** (default no) is only for a **remote_access**
signer. It lets that signer ask for a shell on a key the job brings
along, instead of on a key the host already holds. See
**otpme-shell**(1).

The host needs the user or the role itself for this, not only its name:
it pins a key, and the key is in the object. A host that has not synced
the object yet refuses the job and runs it as soon as the object is
there. This happens with a user or a role that was just created, and it
sorts itself out.

A name nobody ever had is a different thing, and **add** says so right
away instead of letting every host refuse the job for ever.

**del_signer type=*signer_type* signer=*object_id* \[**remove_last_own_signer=***yes*\]**  
Remove a signer. If there is no such signer, nothing changes.  
The user or role does not have to exist any more — see below.

**update_signer type=*signer_type* signer=*object_id* \[**remove_gone=***yes*\] \[**remove_last_own_signer=***yes*\] \[**verify_token_opts=***yes*\] \[**allow_throwaway_key=***yes*\]**  
Pin the current key of the user or role again, for example after a key
change.

**verify_token_opts** and **allow_throwaway_key** change what the signer
may ask for. A job that does not name them leaves them as they are: an
update is usually about the pinned key, and saying nothing must not take
a permission away. This is the only way to change one of them without
removing the signer and adding it again.

**del_signer** and **update_signer** also take the UUID of the signer
entry, as **show_signer** prints it in its first column. They name an
entry on the host, and an entry outlives its user or role.
**add_signer** does not take a UUID: it needs the object.

**del_signer** takes the OID of a user or role that was deleted as well.
Each entry carries the OID it was added under, so the host finds it by
that name even when nothing answers to it any more. An object that was
only renamed is found by its UUID as before, so the new name works and
the old one does too.

**update_signer** is the one that needs the object: it pins the key the
object has now. For a signer whose user or role is gone, name the entry
by its UUID.

A signer whose user or role was deleted is kept, and so is the key a
role pinned for a member it does not have anymore. What they signed is
out there and still has to validate. **remove_gone=yes** drops them,
which is how their keys go once nothing needs them.

A host verifies a **signer_mgmt** job against its **signer_mgmt**
signers, so such a job can take away the permission it runs under. The
host refuses a job that would leave no **signer_mgmt** signer covering
the user who signed it. They could not send another job to that host,
and putting a signer back is itself a **signer_mgmt** job: somebody
would have to walk to the host.

**remove_last_own_signer=yes** allows it. Say it only when you mean to
hand the host over, or when you are at its console. The word is part of
the job, so it stands in the tags you are shown before you sign.

These actions do the same as **otpme-tool show_signer**, **add_signer**,
**del_signer** and **update_signer** run as root on the host.
**otpme-tool del_signer** on the host takes the UUID of the entry as
well, which is the way out when the host cannot be reached by job
anymore.

**service_mgmt**  
Manage systemd services.

**start\|**stop**\|**restart**\|**enable**\|**disable** **unit=***unit***  
Run the action on a systemd unit.

**file_mgmt**  
Manage files.

**put_file path=*path* **--file** *source_file* \[**mode=***mode*\] \[**owner=***user*\] \[**group=***group*\]**  
Write a file on the host. The content comes from *source_file*.

**del_file path=*path***  
Remove a file.

**host_mgmt**  
Switch the host.

**reboot**  
Reboot the host after one minute.

**shutdown**  
Switch the host off after one minute. It stays off until somebody is
standing next to it.

The delay lets the host send the result first. Once the host is down,
nobody would send it.

Upgrading the host is not here. That is the package manager's work, see
**sw_mgmt dist_upgrade**.

**remote_access**  
Hand out a shell on the host.

**shell \[**user=***user*\] \[**command=***command*\] \[**pubkey=***key*\]**  
The host connects out to the master node of its site and speaks SSH
through it. Without **pubkey** the host allows the keys of its own
**authorized_keys** for *user*. With **pubkey** it allows that one key
and no other, and then the signature of the job is the only thing that
gets somebody in. The host takes such a job only from a signer added
with **allow_throwaway_key**.

Do not create this job by hand. Use **otpme-shell**(1), which creates it
and then takes the shell.

Most of these job types give full control over the host, not only the
ones that look like it.

**file_mgmt** writes any file as root. **signer_mgmt** decides who may
command the host at all. **remote_access** hands out a root shell.

**sw_mgmt** and **repo_mgmt** belong in the same group, which is less
obvious: the maintainer scripts of a package run as root, and a
repository says where packages come from. Being allowed to install a
package is being allowed to run code as root.

**service_mgmt** starts and stops what is already on the host, and
**host_mgmt** only switches it off. Those two cannot take the host over,
but they can stop it doing its work.

So add signers only for users you trust with root access on that host.

# COMMANDS

**add \[**--host** *host1,host2*\] \[**--unit** *unit*\] \[**--recursive**\] \[**--role** *role1,role2*\] \[**--group** *group1,group2*\] \[**--arg** *name=value*\]... \[**--file** *path*\] \[**--key** *path*\] \[**--expiry** *time*\] *job_type* *action***  
Create a job and sign it. You need at least one of **--host**,
**--unit**, **--role** or **--group**. They can be combined, and a host
named twice is taken once. The command fails if a required argument is
missing, if an argument is unknown, or if you may not create jobs for
one of the hosts. A **signer_mgmt** job also fails here when it names a
signer that is not a user or a role, or one that does not exist at all.

**list \[**--host** *host*\] \[**--failed**\] \[**--pending**\]**  
List jobs. Shows the time, the job type and action, the arguments, the
number of hosts, the signer and the state of the job. The colour says
how the job stands: grey when the job was taken back, and otherwise the
worst state first — red when a host ran it and it did not work, yellow
when a host would not run it, cyan when a host failed or refused and
that was acknowledged with **ack**, orange while a host has not run it
yet, green when every host ran it.

Grey comes first because a job you took back is over and there is
nothing to do about it. Red would read as something going wrong, which
is the opposite of what happened. A host that ran the job before you
took it back and failed is still in the state of the line (**cancelled,
2 ok, 1 failed**) and in **results**. Nothing waits for an **ack** after
that, see **How long jobs are kept**.

**ack** takes the place of red and yellow, so what somebody has already
seen does not hide the line that is new. It changes nothing about a job
that worked or one that is still running.

**show *job_uuid***  
Show a job and the state on each host: **ok**, **failed**, **refused**
or **pending**. A **refused** line is only shown when there is one (see
**Refused jobs**).

**results \[**--host** *host*\] \[*job_uuid*\]**  
Show the results of a job, or all results of a host. The header line of
each result names the state, in the same colours as **list**: green when
the job worked, yellow when the host refused it, red when it ran and did
not work.

**ack *job_uuid***  
Say that you have seen how a job went. Without this a job that failed,
was refused, or is still waiting for a host is never removed (see **How
long jobs are kept**).

**cancel *job_uuid***  
Cancel a job. Hosts that did not run the job yet will not run it. The
job stays in the list and is shown as cancelled.

# OPTIONS

**--host *host1,host2***  
Hosts or nodes the job is for.

**--unit *unit***  
All hosts of this unit.

**--recursive**  
With **--unit**: also the hosts of all units below it.

**--role *role1,role2***  
All hosts of these roles. A role holds hosts, never nodes, so this never
reaches a node.

**--group *group1,group2***  
All hosts of these groups. A group holds hosts, never nodes.

**--arg *name=value***  
An argument of the job. Use it once for each argument. A value with
commas is a list, for example **packages=tcpdump,ngrep**. The same name
twice is an error.

**--file *path***  
The file that **file_mgmt put_file** writes on the host.

**--key *path***  
The signing key of a repository for **repo_mgmt add_repo**.

**--expiry *time***  
How long hosts may run the job, for example **7D**. The units are **s**,
**m**, **h**, **D**, **W**, **M** and **Y**, see **otpme**(7). Default:
30 days. A host that comes online later does not run an expired job.

**--on-demand**  
Tell the hosts to look now. Without it they find the job on their next
round, which is at most a minute away.

A host told this way does not look at once. A job for a unit is a job
for every host in it, they are all told in the same second, and they
would reach the node together — so each waits a moment of its own first,
up to 10 seconds.

A **remote_access** job is the exception: it is for one host and
somebody is waiting at a terminal for the shell, so that one is fetched
at once.

It says how many hosts heard it. A host that was not listening is not a
failure — it asks on its next round — but it is why a job can take a
minute to start.

**--return-uuid**  
Print the UUID of the job and nothing else. For a script that has to go
on working with the job; it is what **otpme-shell**(1) uses to find the
host at the node.

Global options are available for all commands. See **otpme**(1) for
details.

# SIGNATURES

A job signature covers the job type, the action, all arguments, the
number of hosts and the name of each host. These values are shown to you
as tags before you sign. A long value (more than 64 characters, for
example file content) is shown as its size and its SHA256 hash. You can
compare the hash with **sha256sum**.

The host checks that the tags match the job. So a node can not show you
one job and send another job to the host.

# AUDIT LOG

A job is an order to run something on someone else's machine, so every
step of it is written to the audit log. Where that log goes is set with
**AUDIT_LOG_SERVER** in *otpme.conf*. Without a server the entries go to
*/var/log/otpme/audit.log* on the machine that wrote them. See
**otpme.conf**(5).

On the nodes:

**job_created**  
A job was made. Says the job type, the action, the arguments, the hosts,
the signer and when the job expires. The actor is the token that made
it.

**job_denied**  
Somebody asked for a job for a host they may not make jobs for. Says the
host and that **allow_confd_jobs** is the reason. Written at warning
level.

**job_result**  
A host reported what became of a job. Says the status and the exit code,
and in **ordered_by** the token the job was made with, so a result reads
back to the order. The actor is the host: it reports about itself,
nobody is logged in there. Warning level when the job did not work.

**job_acked / job_cancelled**  
Somebody acknowledged a failed job, or took a job back.

On each host:

**job_started**  
The host checked a job and is about to run it. Says the signer it
verified, by UUID.

**job_done**  
The job finished on the host, with the status and the exit code. Written
once, when the result is there, even if sending it to the nodes has to
be tried again. Warning level when the job did not work.

**job_refused**  
The host will not run a job, with the reason: no signer it trusts for
this job type, a signature that does not hold, a runner that did not
start, or an object the job names that has not reached the host yet.
Written at warning level. The host writes this once per job, not once a
round, so a job that waits for a sync does not fill the log.

Both ends name a host by its FQDN, so the entries of one job fit
together.

A host names the signer by UUID and never by name. It holds no users and
no roles, only the UUIDs it trusts, and a signature carries no name
either. A name in such an entry would be one the host cannot check. The
name is on the nodes, in **job_created**, under the same job UUID.

Example of one job, from both sides:

>     mgmtd: Deploy job_created actor=alice/login job=8a1e1207-... job_type=sw_mgmt \
>            action=upgrade args="packages=openssl" hosts=client1 host_count=1 \
>            signer=alice expiry=1790000000
>     confd: Deploy job_started actor=client1.example.org job=8a1e1207-... \
>            job_type=sw_mgmt action=upgrade signer_uuid=fea7dc2d-...
>     confd: Deploy job_done actor=client1.example.org job=8a1e1207-... \
>            job_type=sw_mgmt action=upgrade status=ok exit_code=0
>     syncd: Deploy job_result actor=client1.example.org job=8a1e1207-... \
>            job_type=sw_mgmt action=upgrade status=ok exit_code=0 \
>            ordered_by=alice/login

# EXAMPLES

The examples use the realm **example.org** and the site **berlin**. An
OID contains a **\|**, so put the argument in quotes.

## Setup

Before the first job, two things are needed.

**otpme-unit config hosts allow_confd_jobs 'role\|example.org/berlin/host-admins'**  
On a node: allow members of the role host-admins to create jobs for the
hosts of the unit **hosts**.

**otpme-tool add_signer --signer-type signer_mgmt 'role\|example.org/berlin/host-admins'**  
On each host, as root: trust the role host-admins for signer_mgmt jobs.
After this, all other signers can be added with jobs (see
**signer_mgmt** below).

## Finding the hosts

A job needs to know which hosts it is for. **otpme-inventory**(1)
answers that.

Which hosts still have the old openssl:

>     $ otpme-inventory search 'openssl=3.0.9*'
>     client1 openssl=3.0.9-1
>     client2 openssl=3.0.9-1

The names of those hosts as one argument for **--host**:

>     $ otpme-inventory search 'openssl=3.0.9*' | cut -d' ' -f1 | sort -u | paste -sd,
>     client1,client2

So the whole thing is two commands:

>     $ hosts=$(otpme-inventory search 'openssl=3.0.9*' | cut -d' ' -f1 | sort -u | paste -sd,)
>     $ otpme-deploy add --host "$hosts" --arg packages=openssl sw_mgmt upgrade

The same works for hardware. Upgrade the firmware package only on the
machines that have that model:

>     $ hosts=$(otpme-inventory search --hardware 'model=PowerEdge R640' | cut -d' ' -f1 | paste -sd,)
>     $ otpme-deploy add --host "$hosts" --arg packages=srvadmin-all sw_mgmt install

When the hosts are a unit, a role or a group, name that instead. It
stays right when a host is added later, and a list of names does not.

## sw_mgmt

**otpme-deploy add --unit hosts --recursive --arg packages=libreoffice sw_mgmt install**  
Install LibreOffice on all hosts of the unit **hosts** and the units
below it.

**otpme-deploy add --host client1 --arg packages=firefox-esr,thunderbird sw_mgmt upgrade**  
Upgrade two installed packages.

**otpme-deploy add --host client1,client2 --arg packages=tcpdump,ngrep --arg autoremove=yes sw_mgmt remove**  
Remove two packages and the packages that are no longer needed.

**otpme-deploy add --host client1 sw_mgmt autoremove**  
Remove packages that are no longer needed.

**otpme-deploy add --unit hosts sw_mgmt dist_upgrade**  
Upgrade every package on all hosts of the unit **hosts**.

## repo_mgmt

**otpme-deploy add --host client1 --arg name=example --arg 'line=deb https://repo.example.org/debian bookworm main' --key example.asc repo_mgmt add_repo**  
Add an apt repository with its signing key from the file
**example.asc**.

**otpme-deploy add --host client1 --arg name=example repo_mgmt del_repo**  
Remove the repository again.

**otpme-deploy add --unit hosts repo_mgmt update**  
Update the package lists.

## signer_mgmt

**otpme-deploy add --host client1 --arg type=sw_mgmt --arg 'signer=role\|example.org/berlin/sw-admins' signer_mgmt add_signer**  
Trust the role sw-admins for sw_mgmt jobs on client1.

**otpme-deploy add --unit hosts --recursive --arg type=service_mgmt --arg 'signer=user\|example.org/berlin/alice' signer_mgmt add_signer**  
Trust the user alice for service_mgmt jobs on all hosts of the unit
**hosts** and the units below it.

**otpme-deploy add --host client1 --arg type=repo_mgmt --arg 'signer=role\|example.org/berlin/repo-admins' --arg tags=deploy,berlin signer_mgmt add_signer**  
Add a signer with two tags.

**otpme-deploy add --unit hosts --recursive --arg type=service_mgmt --arg 'signer=user\|example.org/berlin/alice' signer_mgmt update_signer**  
Pin the new key of alice, for example after alice changed the sign key.

**otpme-deploy add --host client1 --arg type=sw_mgmt --arg 'signer=role\|example.org/berlin/sw-admins' signer_mgmt del_signer**  
Remove the signer again.

**otpme-deploy add --host client1 --arg type=sw_mgmt signer_mgmt show_signer**  
Ask client1 which sw_mgmt signers it holds. The answer comes with
**otpme-deploy results**, and its first column is the UUID of each
entry.

**otpme-deploy add --host client1 --arg type=sw_mgmt --arg signer=fea7dc2d-3c41-4a0e-9d2f-1b6c8e5a7d90 signer_mgmt del_signer**  
Remove a signer by the UUID of its entry. Use this where the OID does
not say which entry you mean — a name that was given to a second object,
or an entry **show_signer** lists and you cannot place. A signer whose
user or role was deleted can be removed by its OID as well.

## service_mgmt

**otpme-deploy add --unit hosts --arg unit=cups.service service_mgmt restart**  
Restart CUPS on all hosts of the unit **hosts**.

**otpme-deploy add --host client1 --arg unit=ssh.service service_mgmt enable**  
Start SSH at boot.

**otpme-deploy add --host client1 --arg unit=bluetooth.service service_mgmt stop**  
Stop a service.

## file_mgmt

**otpme-deploy add --host client1 --arg path=/etc/motd --arg mode=0644 --file motd.txt file_mgmt put_file**  
Write /etc/motd with the content of the local file **motd.txt**.

**otpme-deploy add --host client1 --arg path=/etc/app/app.conf --arg mode=0640 --arg owner=root --arg group=app --file app.conf file_mgmt put_file**  
Write a file with owner, group and mode. The directory must exist.

**otpme-deploy add --host client1 --arg path=/etc/motd file_mgmt del_file**  
Remove a file.

## host_mgmt

**otpme-deploy add --host client1 --expiry 1h host_mgmt reboot**  
Reboot client1. If the host is offline for more than one hour, it does
not reboot later.

**otpme-deploy add --host client1 --expiry 10m host_mgmt shutdown**  
Switch client1 off. Give it a short expiry: a host that was offline and
comes back should not switch itself off hours later.

## Jobs and results

**otpme-deploy list**  
List all jobs.

**otpme-deploy list --host client1**  
List the jobs for client1.

**otpme-deploy list --pending**  
List the jobs that at least one host did not run yet.

**otpme-deploy list --failed**  
List the jobs that failed on at least one host.

**otpme-deploy show 8a1e1207-f626-42ff-b538-60b7b4223f31**  
Show a job and its state on each host.

**otpme-deploy results 8a1e1207-f626-42ff-b538-60b7b4223f31**  
Show the results of a job.

**otpme-deploy results --host client1**  
Show all results of client1.

**otpme-deploy ack 8a1e1207-f626-42ff-b538-60b7b4223f31**  
Say that you have seen how a job went, so it can be removed.

**otpme-deploy cancel 8a1e1207-f626-42ff-b538-60b7b4223f31**  
Cancel a job.

# FILES

*/var/log/otpme/confd/*  
Full output of each job, on the host.

*/var/spool/otpme/confd/*  
Jobs, results and markers of confd, on the host.

# SEE ALSO

**otpme**(7), **otpme-tool**(1), **otpme-host**(1), **otpme-unit**(1),
**otpme-inventory**(1), **otpme-shell**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
