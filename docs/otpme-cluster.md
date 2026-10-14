# NAME

otpme-cluster - show the cluster of a site, move the master role, set
the votes

# SYNOPSIS

**otpme-cluster status** \[**--diff**\] \[**--full**\]
\[**--full-index**\]  
**otpme-cluster master_failover** \[**--to** *node*\] \[**--random**\]
\[**--wait**\]  
**otpme-cluster required_votes** *votes*

# DESCRIPTION

The cluster of a site is the nodes of that site. Every node runs
**clusterd**, and that is what keeps them alike: a write on one node
goes to the others, and so do the sessions and the short-lived states
that go with a login. One node holds the master role, and that is the
node every object of the site is written to.

This is not the sync to the hosts and to the other sites, that is
**syncd**. See **otpme**(7).

**otpme-cluster** is how you look at that from the outside and how you
take a hand in it. Three things: **status** says where the cluster
stands, **master_failover** hands the master role to another node, and
**required_votes** sets how many votes the site needs.

It works differently from every other OTPme command. It runs on a node,
as root, and talks to the **clusterd** of the nodes directly — not
through **mgmtd**, so there is no token and no ACL. That is on purpose:
a site without a quorum refuses management, and that is exactly when
these questions are asked.

So you need a root shell on one of the nodes, the OTPme daemon has to be
running there, and the machine has to be a node. On a host the command
says so and stops. It also needs the node install (**pip install
'otpme\[node\]'**); without it the command is there but refuses to run.

# COMMANDS

**status \[**--diff**\] \[**--full**\] \[**--full-index**\]**  
Ask every enabled node of this site where it stands.

One line per node: whether it has a quorum, which node it thinks is
master, and three checksums — the objects of the tree, the data objects,
and the sessions. Above them one line for the site. See **WHAT STATUS
SHOWS**.

Every node is asked at the same time, and a node that does not answer is
**Offline**. Nothing is written, and nothing is decided here: the
command reads.

**master_failover \[**--to** *node*\] \[**--random**\] \[**--wait**\]**  
Hand the master role to another node.

Without an option the node you run it on takes the role. With **--to**
the named node takes it. With **--random** a node is picked, which only
works on the node that holds the role.

The role is elected and not configured, so this does not set it: it
makes the node that is to have it win the next election. See **MOVING
THE MASTER ROLE**.

**required_votes *votes***  
Set how many votes the site needs for a quorum.

**0** puts it back to the default, which is half the enabled nodes. See
**VOTES AND QUORUM**.

# OPTIONS

**--diff**  
Say which objects differ. Only with **status**, and only where the nodes
do not hold the same thing. See **FINDING WHAT DIFFERS**.

**--full**  
Read every object instead of asking the index for its checksum. Slow on
a big site, and the only way to see that the index of a node says the
wrong thing about an object.

**--full-index**  
Compare the whole index entry of every object instead of the object.
Catches what the object checksum does not: an attribute or an ACL that
is in the index of one node and not of another.

**--to *node***  
The node that is to take the master role. It has to be a node of this
site.

**--random**  
Pick the node to hand the role to. Only a node that is in sync and may
be master is picked. Run it on the node that holds the role; another
node answers "Node not the master node".

**--wait**  
Wait instead of giving up. The role is not handed over while a
management job is running on the master, and a node that is not ready
cannot take it — with this the command keeps trying until it can.

Global options are available for all commands. See **otpme**(1) for
details.

# VOTES AND QUORUM

Every node has a vote, and the vote is the time that node was last in
sync with the master. A vote of zero says "I cannot be master". The
whole of it is in **otpme-node**(1), under **The Master Role**.

Two numbers are counted from those votes:

**current votes**  
How many nodes can be master right now: this node, plus every node it is
connected to that answers with a vote other than zero. A node that is
online but has not finished its sync with the master does not count.  
Each node counts for itself, which is why **status** shows the number
per node. Two nodes that answer with different numbers are two nodes
that see different parts of the site.

**required votes**  
How many of them the site needs.  
Unset, which is the default, this is half the enabled nodes of the site
— and half is enough, because the count only has to reach it. Three
enabled nodes need two votes, four need two as well, two need one.  
**otpme-cluster required_votes** sets a number of your own.

A node with a quorum works. A node without one refuses nearly
everything: **mgmtd**, **authd**, **joind**, **ssod**, **fsd**, **racd**
and **idled** answer "No cluster quorum". Only the daemons the node
needs to find its way back keep answering: **hostd**, **syncd**,
**clusterd** and **backupd**.

The quorum is one of two things that have to be true. The other is the
site itself: a node serves the site when the nodes it has are at least
the required votes *and* it has synced with the master at all
(*/var/spool/otpme/node_synced*). Where that does not hold, the same
daemons answer "Cluster not ready", and **ldapd** is stopped outright —
it is the one daemon that is started and stopped with this, instead of
refusing. That is the **Cluster status** line of **status**, and it is
read from the master node.

# WHAT STATUS SHOWS

>     $ otpme-cluster status
>     Reading cluster data from node: node1
>     Reading cluster data from node: node2
>     Reading cluster data from node: node3
>     Cluster status: Online
>     node1 (Quorum: 3) (Master: node1) (Objects: 7b1c...) (Data: 4f0a...) (Sessions: e391...)
>     node2 (Quorum: 3) (Master: node1) (Objects: 7b1c...) (Data: 4f0a...) (Sessions: e391...)
>     node3 (Quorum: 3) (Master: node1) (Objects: 7b1c...) (Data: 4f0a...) (Sessions: e391...)

The first line is the site, as the master node sees it. **Online** means
the site is served; **Offline** means it is not, see **VOTES AND
QUORUM**. A number set with **required_votes** is named here as a
warning, because it is a number that does not follow the site.

Then one line per node:

**(Quorum: *n***)****  
The votes that node counted, itself included. **False** means that node
has no quorum.

**(Master: *node***)****  
Who that node thinks holds the master role. All lines should say the
same name.

**(Objects: ...) (Data: ...) (Sessions: ...)**  
What that node holds, in three checksums: the objects of the tree, the
data objects, and the sessions. Nodes that hold the same thing show the
same three.

A node can also be a word instead of a line of values:

**Disabled**  
The node object is disabled. It is not asked, it takes no part in the
election, and it does not count towards the required votes.

**(Offline)**  
The node did not answer. Either it is down, or its **clusterd** is not
answering, or it has no quorum to answer with.

**(Error)**  
The node answered, but not with its checksums.

The colours say the same thing more quickly: green is a node with a
quorum that holds what the master holds, yellow is a node without a
quorum or one that holds something else, red is a node that is gone or
does not know who is master, grey is a disabled node.

# FINDING WHAT DIFFERS

A node whose checksums differ from the master's is a node that holds
something else. **--diff** says what:

>     $ otpme-cluster status --diff
>     Object user|example.org/berlin/john differs: node1=2b9f..., node2=c417...
>     Data object host_inventory|example.org/berlin/8f3c... missing on: node2 (present on: node1, node3)
>     Misses: 1
>     Diffs: 1
>
>     Cluster status: Online
>     ...

**differs** means every node has the object and they do not agree about
it. **missing on** names the nodes that do not have it at all. The two
counts at the end are how many of each there are.

Two nodes have to be online for this, and the nodes have to disagree in
the first place: where the checksums match there is nothing to list.

By default the checksums come from the index, which is what the nodes
compare all day anyway. Two options read deeper:

**--full** reads every object from disk and works out its checksum
again. Use it when the index of a node may be saying the wrong thing
about an object. It reads the whole site on every node, so it takes its
time.

**--full-index** compares the whole index entry of every object. An
attribute or an ACL that one node has in its index and another does not
shows up here and nowhere else.

An object that the index of a node lists while its file is gone is left
alone by all of this, and the node writes a warning to its log instead.
**otpme-tool index fix** is what repairs it — afterwards, because how
such an entry got there is worth more than the repair.

# MOVING THE MASTER ROLE

**master_failover** does not move the role by hand. It makes the node
that is to have it win the next election, and the nodes do the rest. In
order:

-   The node you run it on asks itself whether the site has a quorum.
    Without one nothing happens: "No cluster quorum".

-   The node that is to take the role is asked for its vote. A node that
    cannot be master is not switched to — it would hand the role
    straight back.

-   The node that holds the role is asked to give it up. It says no
    while a management job is running on it, and the answer names the
    job. That is what **--wait** waits for.

-   The new node starts the failover. Every node of the site is told
    that one is going on, and while it is, they refuse what they would
    otherwise answer: "Ongoing master failover". Logins keep working —
    **authd** is the one daemon that goes on answering.

-   The new node stamps its own sync file until it wins the election,
    the old master stops **idled** and **racd** and gives up the
    floating IP of the site, and the new one starts them and takes it.
    When the address is in place the nodes answer again.

So a failover is a short break for everything but logins, and it is over
in seconds unless something is waited for.

The node that already holds the role is refused: "Node already the
master node".

There is a second way to say which node should hold the role, and it is
not this command: **preferred_master_node** on the site. **clusterd**
hands the role to that node once, when the daemon has started and the
site has a quorum, and never again while it runs. Use it for the node
that should have the role after a restart, and use **master_failover**
for right now. See **otpme**(7).

**MASTER_FAILOVER_SYNC** in **otpme.conf**(5) adds one step before the
switch: the new master syncs the data objects and the sessions once
more, so nothing of them is lost that the old master had and it did not.
That makes the break longer, which is why it is off by default.

# REQUIRED VOTES

**required_votes** writes the number on the site object, and from there
it reaches the other nodes like every other write. It counts from the
next quorum check, a few seconds later.

Set it when the default does not say what you mean. Four nodes in two
rooms need three votes, or each room has a quorum of its own and both
halves go on writing.

**status** names it as a warning for as long as it is set, because the
number stays as it is when the site grows: set it to 2 on a three-node
site, add two nodes, and the site still has a quorum with two of five.

**0** takes it back to the default. Setting the number it already has
changes nothing and says so.

# TWO NODES

A site with two enabled nodes runs in two-node mode, and two nodes mean
one required vote: each of them keeps the site alive alone.

While the other node is away, a write is not kept for it. It is written
here and it is not journalled, because there is nobody to send it to —
the node gets it when it is back, from the sync that runs as soon as it
connects. A delete is kept, because a delete that is lost brings the
object back.

**required_votes 1** puts a node in that mode as well, as soon as it has
no other node online. That is how a node of a bigger site is made to go
on working alone, and it is also how two halves of a site go on writing
side by side. Both are what the number is for, and which of the two you
get is yours to know.

# FILES

*/var/spool/otpme/node_sync_time*  
When this node was last in sync with the master. This is where its vote
is read from.

*/var/spool/otpme/node_synced*  
Says that this node has synced with the master at all. Without it the
node serves nothing, see **VOTES AND QUORUM**.

*/var/spool/otpme/cluster_out_journal/, */var/spool/otpme/cluster_in_journal/**  
The writes on their way to the other nodes, and the ones that came from
them. See **otpme-node**(1).

# EXAMPLES

## Where does the cluster stand

**otpme-cluster status**  
Who is master, who has a quorum, who holds what.

**otpme-cluster status --diff**  
The same, and the objects the nodes do not agree about.

**otpme-cluster status --diff --full**  
The same, with every object read from disk. Use it when the index may be
wrong.

## Move the master role

**otpme-cluster master_failover --to node2**  
Hand the role to *node2*.

**otpme-cluster master_failover**  
Take the role, run on the node that is to have it.

**otpme-cluster master_failover --random --wait**  
Run on the master before you take it down: the role goes to one of the
other nodes, and the command waits for the jobs that are still running.

## Votes

**otpme-cluster required_votes 3**  
Four nodes in two rooms: three votes, so one room alone cannot write.

**otpme-cluster required_votes 1**  
One node is enough. A node left alone goes on serving the site.

**otpme-cluster required_votes 0**  
Back to the default, half the enabled nodes.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-node**(1), **otpme-site**(1),
**otpme.conf**(5)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
