#!/bin/bash

OTPME_CONF="/etc/otpme/otpme.conf"
BACKUP_DIR="/var/backups/otpme"
BACKUP_INCLUDE="
/etc/otpme
/var/lib/otpme
/var/log/otpme
/var/spool/otpme
/var/cache/otpme
/etc/passwd.cache
/etc/passwd.cache.ixuid
/etc/passwd.cache.ixname
/etc/group.cache
/etc/group.cache.ixgid
/etc/group.cache.ixname
"

if [ ! -e "$OTPME_CONF" ] ; then
	echo "Missing $OTPME_CONF:"
	exit 1
fi

source "$OTPME_CONF"

start_backup () {
	local BACKUP_NAME="$1"
	local DATE="`date +%Y-%m-%d-%s`"
	local YEAR="`date +%Y`"

	if [ "$BACKUP_NAME" == "" ] ; then
		BACKUP_NAME="$DATE"
	fi

	BACKUP_FILE="$BACKUP_DIR/otpme-$BACKUP_NAME-$INDEX.tgz"

	# Remove old backups.
	find "$BACKUP_DIR" -type f -iname "otpme-$YEAR-*.tgz" -mtime +1 -exec rm {} \;

	if [ ! -d "$BACKUP_DIR" ] ; then
		mkdir "$BACKUP_DIR"
	fi

	echo "Writing $BACKUP_FILE..."
	tar cfzp "$BACKUP_FILE" $BACKUP_INCLUDE
}

restore_backup () {
	for E in $BACKUP_INCLUDE ; do
		echo "Removing $E...."
		rm -r "$E"
	done

	echo "Restoring $1..."
	cd /
	tar xfzp "$1"
}

if [ "$1" = "restore" ] ; then
	BACKUP_NAME="$2"
	if [ "$BACKUP_NAME" == "" ] ; then
		BACKUP_FILE="$(ls -1t $BACKUP_DIR/* | head -n1)"
	else
		if [ -f "$BACKUP_NAME" ] ; then
			BACKUP_FILE="$BACKUP_NAME"
		else
			BACKUP_FILE="$BACKUP_DIR/otpme-$BACKUP_NAME-$INDEX.tgz"
		fi
	fi
	if [ ! -f "$BACKUP_FILE" ] ; then
		echo "No such file: $BACKUP_FILE"
		exit 1
	fi

	pkill -9 otpme-agent
	pkill -9 otpme-controld
	pkill -9 otpme-controld
	pkill -9 otpme-cached
	pkill -9 otpme-authd
	pkill -9 otpme-mgmtd
	pkill -9 otpme-syncd
	pkill -9 otpme-joind
	pkill -9 otpme-ldapd
	pkill -9 otpme-hostd
	pkill -9 otpme-scriptd

	otpme-tool index stop
	otpme-tool cache stop
	restore_backup "$BACKUP_FILE"
	otpme-tool index start
	otpme-tool cache start
else
	BACKUP_NAME="$1"
	CHECK="$(ls -1 /var/lib/otpme/tree 2> /dev/null)"
	if [ "$CHECK" = "" ] ; then
		echo "Nothing to backup."
		exit
	fi
	otpme-tool index stop
	otpme-tool cache stop
	start_backup "$BACKUP_NAME"
	otpme-tool index start
	otpme-tool cache start
fi
