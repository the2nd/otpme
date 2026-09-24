# NAME

otpme-inventory - show the system, the packages and the hardware of
hosts

# SYNOPSIS

**otpme-inventory** *command* \[*options*\]

# DESCRIPTION

**otpme-inventory** shows which system a host runs, which packages are
installed on it, and what it is made of. You can also search for hosts
that have a package, run a system version, or have certain hardware.

Use it to find the hosts a job has to run on, for example all hosts with
an old version of a package. See **otpme-deploy**(1). Use it to find a
machine by its serial number, or to see how much memory and disk a host
has.

The **confd** daemon on each host (and node) reports this data to the
nodes of its site. It checks the host every 60 seconds and only sends
what changed. It does not take stock while a job is running on the host.
A package manager at work is no good moment for it, the next round does
it.

The data is stored in two places:

-   The OS and the OS version are stored on the host object (**os**,
    **os_version**). They are shown by **otpme-host show**.

-   The packages and the hardware are stored in a separate inventory
    object for each host. Host objects are synced to all hosts, and the
    package lists of all hosts should not be. The inventory stays on the
    nodes of the host's site.

Changing the inventory does not change the last modified time of the
host.

To see the inventory of a host your token has to be named in the
**allow_inventory** config parameter of that host. Hosts you may not see
are left out of search results. See **PERMISSIONS** below.

Only hosts of the own site are shown.

The hardware is read on any Linux host. Package lists need a package
manager the host knows, which today means Debian and Ubuntu. A host
without one still reports its system and its hardware.

# COMMANDS

**show *host***  
Show the OS, the OS version, the number of packages, the vendor, the
model, the serial number and the time of the last update.

**packages \[**--filter** *pattern*\] *host***  
List the packages of a host, one per line with name and version.

**hardware *host***  
Show what a host is made of: CPU, memory, disks, serial number and so
on. Sizes are shown in human form, for example **9.7G**. Says so if the
host has not reported its hardware yet.

**search \[**--host** *host*\] \[**--os-version** *version*\] \[**--hardware** *expression*\] \[*package*\]**  
Find hosts by package, by OS version, or by hardware. *package* is a
package name, or a name and a version in the form *name***=***version*.
Both can contain wildcards (**\***). Every option you give has to match,
so they narrow the result down. You have to give at least one of them.

Each line says a host and what made it match. With a *package* that is
the package and its version, one line per package. With **--hardware**
it is the value that matched. A host has several disks, and then only
the disks that match are shown, with their name. So a search for
**'disk_size\>=100G'** shows **sdb=150.0G** and not all disks of the
host.

# OPTIONS

**--filter *pattern***  
Only list packages whose name matches the pattern, for example
**'python3-\*'**.

**--host *host***  
Only this host. Use it to search the packages of one host instead of
listing all of them.

**--os-version *version***  
Only hosts with this OS version, for example **debian-12**. Wildcards
are allowed, for example **'debian-\*'**.

**--hardware *expression***  
Only hosts whose hardware matches. The expression is a field, an
operator and a value.

-   *field***=***value* matches the value. Wildcards are allowed, for
    example **'model=PowerEdge\*'**.

-   *field***\>***value*, *field***\<***value*, *field***\>=***value*
    and *field***\<=***value* compare. Only fields that are a number can
    be compared.

Put the expression in quotes. **\>** and **\<** are redirections in the
shell, and **\*** is a file name pattern.

Global options are available for all commands. See **otpme**(1) for
details.

# PERMISSIONS

Who may read the inventory of a host is set with the **allow_inventory**
config parameter. It holds tokens and roles. A token may read the
inventory when it is named, or when it is in a role that is named. Roles
inside roles count too.

You can set it on a host, on a unit, on a site. The most specific one
wins, like every config parameter. So you can allow a role on one unit
and nowhere else.

If it is not set, nobody may read the inventory. The admin token and
tokens in the admin role are the exception, they always may. For a node
only the realm admin may, not a site admin, the same as for an ACL on a
node.

This is a config parameter and not an ACL on purpose. An inventory is
not one more attribute of a host. It is the serial number, what is
installed and what the machine is built from. With an ACL a plain
**view** on the host would carry all of it, and **view** is given out so
somebody can read a status.

Example:

> otpme-host config client1 allow_inventory
> 'role\|example.org/berlin/it-support'

# OS AND OS VERSION

**os** is **Linux**, **Windows** or **MacOS**. **os_version** is the ID
and the version from */etc/os-release*, for example **debian-13** or
**ubuntu-24.04**. A system without a version number uses its code name,
for example **debian-trixie**.

# PACKAGE NAMES

Package names are the names dpkg uses. A multi-arch package has its
architecture in the name, for example **libc6:amd64**. Only fully
installed packages are listed.

# HARDWARE FIELDS

The host reads all of this from files, so nothing has to be installed
for it. A field that a host cannot read is left out. On a virtual
machine most of the DMI fields are empty.

These fields can be searched with **--hardware**:

**vendor, **model**, **serial**, **asset_tag**, **sku****  
What the board says about itself, from */sys/class/dmi/id*. **serial**
is what Dell calls the Service Tag. You can also write **service_tag**
in a search, it means the same field. **asset_tag** is the tag your own
IT sets, it is a different field.

**cpu_model, **cpu_count****  
The CPU and how many logical CPUs there are, from */proc/cpuinfo*.
**cpu_count** can be compared.

**memory**  
How much memory the host has, from */proc/meminfo*. Can be compared.
Write it as a size, for example **8G**.

**disk, **disk_size****  
One entry per disk, from */sys/block*. **disk** is the name, for example
**sda**. **disk_size** is the size and can be compared. A host matches
when any of its disks matches.

**virtual, **virt_type****  
Whether the host is a virtual machine, and on what. **virtual** is
**yes** or **no**. **virt_type** is **kvm**, **vmware**, **virtualbox**,
**xen**, **hyperv** and so on.

**bios_version, **chassis_type****  
The BIOS version, and what kind of case this is (**rack-mount-chassis**,
**laptop**, **desktop** and so on).

**hardware** also shows the board, the BIOS vendor and the BIOS date.
Those are not searched, they are only read off the host.

# EXAMPLES

## One host

Show the system of a host, how many packages it has and which machine it
is:

>     $ otpme-inventory show client1
>     host: client1
>     os: Linux
>     os_version: debian-13
>     packages: 686
>     vendor: Dell Inc.
>     model: PowerEdge R640
>     serial: ABC1234
>     last_update: 2026-09-24 20:13

Show what it is made of:

>     $ otpme-inventory hardware client1
>     bios_version: 2.19.1
>     chassis_type: rack-mount-chassis
>     cpu_count: 16
>     cpu_model: Intel(R) Xeon(R) Silver 4216
>     memory: 31.2G
>     model: PowerEdge R640
>     serial: ABC1234
>     vendor: Dell Inc.
>     virtual: no
>     disk: sda 223.6G PERC H730P
>     disk: sdb 1.8T PERC H730P

List its packages, all of them or only some:

>     $ otpme-inventory packages client1
>     $ otpme-inventory packages --filter 'libreoffice*' client1

## Find hosts by package

**otpme-inventory search openssl**  
Show all hosts that have the package openssl, with its version.

**otpme-inventory search 'openssl=3.0.\*'**  
Show the hosts that have a 3.0 version of openssl.

**otpme-inventory search --host client1 'python3-\*'**  
Show the python3 packages of client1. Without **--host** this asks every
host.

**otpme-inventory search --os-version debian-12 firefox-esr**  
Show the Debian 12 hosts that have firefox-esr.

One line per package, so a host with four matching packages is on four
lines:

>     $ otpme-inventory search --host client1 'libc6*'
>     client1 libc6-dbg:amd64=2.36-9+deb12u14
>     client1 libc6-dev:amd64=2.36-9+deb12u14
>     client1 libc6-i386=2.36-9+deb12u14
>     client1 libc6:amd64=2.36-9+deb12u14

## Find hosts by system

**otpme-inventory search --os-version debian-12**  
Show all hosts that run Debian 12.

**otpme-inventory search --os-version 'debian-\*'**  
Show all Debian hosts, whatever the version.

**otpme-tool search object_type=host attribute=os_version value=debian-12 return_type=name**  
The same search with **otpme-tool**, which gives the names only.

## Find hosts by hardware

**otpme-inventory search --hardware service_tag=ABC1234**  
Find the machine with this Dell service tag.

**otpme-inventory search --hardware 'model=PowerEdge\*'**  
Show all Dell PowerEdge servers.

**otpme-inventory search --hardware virtual=no**  
Show all hosts that are not virtual machines.

**otpme-inventory search --hardware 'memory\<8G'**  
Show all hosts with less than 8 GB of memory.

**otpme-inventory search --hardware 'cpu_count\>=8'**  
Show all hosts with 8 CPUs or more.

The line says what matched, so a search for memory shows the memory:

>     $ otpme-inventory search --hardware 'memory>=4G'
>     client1 7.8G
>     dev1 9.7G
>     server1 31.2G

A host has several disks, so only the disks that match are shown:

>     $ otpme-inventory search --hardware 'disk_size>=100G'
>     client1 sda=223.6G
>     dev1 sdc=100.0G
>     server1 sdb=150.0G

Search by disk name the same way. **disk=sda** shows the **sda** of
every host with its size:

>     $ otpme-inventory search --hardware disk=sda
>     client1 sda=223.6G
>     dev1 sda=48.0G
>     server1 sda=32.0G

## Narrow it down

Every option has to match, so you can put them together.

**otpme-inventory search --hardware 'disk_size\>1T' --os-version debian-13**  
The Debian 13 hosts that have a disk larger than 1 TB.

**otpme-inventory search --os-version debian-12 --hardware virtual=no openssl**  
The physical Debian 12 machines that have openssl.

# SEE ALSO

**otpme**(7), **otpme-deploy**(1), **otpme-host**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
