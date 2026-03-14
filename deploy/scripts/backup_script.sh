#!/bin/bash
if [ "$backup_hook" = "pre" ] ; then
	# do pre backup stuff.
	echo "Pre backup"
fi
if [ "$backup_hook" = "post" ] ; then
	# do post backup stuff.
	echo "Post backup"
fi
