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

The OS, the OS version, the packages and the hardware are stored in a
separate inventory object for each host, not on the host object. All
four are what the host reported about itself, and an inventory has to
stand on its own. Host objects are synced to all hosts, and the package
lists of all hosts should not be, so the inventory stays on the nodes of
the host's site.

Changing the inventory does not change the last modified time of the
host.

To see the inventory of a host your token has to be named in the
**allow_inventory** config parameter of that host. Hosts you may not see
are left out of search results. See **PERMISSIONS** below.

Shown are the hosts whose inventory this site keeps: its own, and those
of other sites that report here, see **A CENTRAL INVENTORY**.

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
host. Behind the size comes what says which disk it is, the vendor, the
model and the serial, where the host knows them: **sdb=150.0G(SEAGATE
ST1000NM0055 ZA12345)**.

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

For a host of another site that reports here, see **A CENTRAL
INVENTORY**, there is a second parameter:

**allow_foreign_inventory (list)**  
Who may read the inventories of hosts that are not ours. Set on the site
that keeps them, it holds tokens and roles like **allow_inventory** and
decides instead of the **allow_inventory** of the host.  
Unset means the host decides, with its own **allow_inventory** at the
host, its unit and its site of origin.  
It does not touch the hosts of this site, those always go by
**allow_inventory**.  
Object types: site

# A CENTRAL INVENTORY

By default a host reports to the site it belongs to, and that site
answers for it. A realm that wants one place to ask "which machines do
we have" points its hosts somewhere else.

Two parameters, one at each end, because a host saying where it wants to
report is not the same as a site agreeing to keep it.

**inventory_site (str)**  
Where a host reports its inventory. Set it on a host, a unit or a site;
the most specific one wins, like every config parameter. Unset means the
site the host belongs to.  
Object types: site, unit, host, node

**inventory_trusts (list)**  
The sites whose hosts this site keeps inventories for. Unset means none,
and then a host of another site is refused.  
Object types: site

Example, with every host of *berlin* reporting to *munich*:

>     otpme-site config berlin inventory_site munich
>     otpme-site config munich inventory_trusts berlin

Both sites have to be in the same realm. An inventory is kept per realm,
and a host of another realm is refused whatever is set here.

Who may read them is the **allow_foreign_inventory** of this site, and
where that is unset the **allow_inventory** of the host, which resolves
at that host, its unit and its site of origin. So either end can decide:
set it here and this site says who reads, leave it and the site the data
is about keeps saying. See **PERMISSIONS**.

A host that reported to its own site before keeps that inventory there.
It is not moved and not deleted, and it stops being updated.

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
The one thing that is nicer with a package installed is the name of a
controller: it comes from the PCI ID database (**pciutils** or
**hwdata**), and without it a controller is its IDs and its driver.

Everything a host reports can be searched with **--hardware**. These are
the fields:

**vendor, **model**, **serial**, **asset_tag**, **sku****  
What the machine says about itself, from */sys/class/dmi/id*. **serial**
is what Dell calls the Service Tag. You can also write **service_tag**
in a search, it means the same field. **asset_tag** is the tag your own
IT sets, it is a different field.

**board_vendor, **board_model**, **board_serial****  
The same three for the mainboard. Useful when a board series turns out
to be faulty: the machine can carry the name of the maker who built it,
the board carries the name of who made the board.

**cpu_model, **cpu_count****  
The CPU and how many logical CPUs there are, from */proc/cpuinfo*.
**cpu_count** can be compared.

**memory**  
How much memory the host has, from */proc/meminfo*. Can be compared.
Write it as a size, for example **8G**.

**disk, **disk_size**, **disk_serial**, **disk_vendor**, **disk_model****  
One entry per disk, from */sys/block*. **disk** is the name, for example
**sda**. **disk_size** is the size and can be compared. **disk_serial**
is the serial number of the disk, the one on the sticker.
**disk_vendor** and **disk_model** are who made it and what it is
called, for example **ATA** and **OCZ-VERTEX3 MI**. Use them when a
whole series of disks turns out to be faulty.  
A SATA disk says **ATA** as its vendor, whatever is written on it: that
is the name of the interface and not of the maker, and the maker is part
of the model. A SAS or SCSI disk says **SEAGATE** or **DELL**. So search
a SATA disk by its model.  
A host matches when any of its disks matches, and the answer names the
disks that did.  
The serial is read from the disk itself, so not every disk has one: NVMe
disks report it directly, SCSI and SATA disks through their serial
number page.

**nic**  
The network cards, from */sys/class/net*. Only what has hardware behind
it, so the loopback, the bridges, the bonds, the VLAN interfaces and the
tunnels are left out: those are not hardware and are named after whoever
configured them.  
Matches the name the kernel gave a card (**eno1**), its MAC, its vendor,
the name on the card or the name of the chip on it. Search it by MAC
when a DHCP lease or a switch port is all you have and the question is
which host that is.

**controller**  
The storage controllers, from */sys/bus/pci/devices*: every PCI device
of the mass storage class. Matches the PCI address of a controller
(**0000:18:00.0**), its vendor, the name on the card (**PERC H730P
Mini**) or the name of the chip on it (**MegaRAID SAS-3 3108**).  
The answer is the disks that hang on the controller, because that is
what a controller is looked for.  
The names come from the PCI ID database of the host
(*/usr/share/misc/pci.ids* or */usr/share/hwdata/pci.ids*). A host
without one reports the IDs and the driver, and then only those can be
searched.

**virtual, **virt_type****  
Whether the host is a virtual machine, and on what. **virtual** is
**yes** or **no**. **virt_type** is **kvm**, **vmware**, **virtualbox**,
**xen**, **hyperv** and so on.

**bios_vendor, **bios_version**, **bios_date****  
The BIOS. **bios_date** is written the way the board writes it, usually
**mm/dd/yyyy**, so search it with a wildcard.

**chassis_type**  
What kind of case this is (**rack-mount-chassis**, **laptop**,
**desktop** and so on).

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
>     disk: sda 223.6G DELL PERC H730P serial=6F4EE0803A2E4900 controller=0000:18:00.0
>     disk: sdb 1.8T DELL PERC H730P serial=6F4EE0803A2E4901 controller=0000:18:00.0
>     controller: 0000:18:00.0 Broadcom / LSI PERC H730P Mini MegaRAID SAS-3 3108 vendor_id=1000 device_id=005d subsystem_id=1028:1f47 driver=megaraid_sas
>     nic: eno1 ec:f4:bb:11:22:33 Intel Corporation I350 Gigabit Network Connection vendor_id=8086 device_id=1521 driver=igb

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
>     client1 sda=223.6G(DELL PERC H730P 6F4EE0803A2E4900)
>     dev1 sdc=100.0G(QEMU QEMU HARDDISK)
>     server1 sdb=150.0G(SEAGATE ST1000NM0055 ZA12345)

The other way round, to find the host a disk sits in when all you have
is the disk:

>     $ otpme-inventory search --hardware disk_serial=ZA12345
>     server1 sdb=150.0G(SEAGATE ST1000NM0055 ZA12345)

Or every host that has a disk of a model, when a series turns out to be
faulty:

>     $ otpme-inventory search --hardware 'disk_model=ST1000NM*'
>     server1 sdb=150.0G(SEAGATE ST1000NM0055 ZA12345)
>     server2 sdb=150.0G(SEAGATE ST1000NM0055 ZA67890)

Ask for a controller, and the answer is the disks that hang on it:

>     $ otpme-inventory search --hardware 'controller=PERC H730P*'
>     server1 PERC H730P Mini(sda=223.6G,sdb=1.8T)
>     server2 PERC H730P Mini(sda=223.6G)

Which host a MAC belongs to:

>     $ otpme-inventory search --hardware nic=ec:f4:bb:11:22:33
>     server1 eno1=ec:f4:bb:11:22:33(Intel Corporation I350 Gigabit Network Connection)

Search by disk name the same way. **disk=sda** shows the **sda** of
every host with its size:

>     $ otpme-inventory search --hardware disk=sda
>     client1 sda=223.6G(DELL PERC H730P 6F4EE0803A2E4900)
>     dev1 sda=48.0G(QEMU QEMU HARDDISK)
>     server1 sda=32.0G(QEMU QEMU HARDDISK)

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
