#!/bin/bash
# The following variables will be set:
# 		$share_name
# 		$share_root
#
# The following variables may be set:
# 		$force_group
# 		$force_create_mode
# 		$force_directory_mode
#
#if [ "$force_group" != "" ] ; then
#	ADDITIONAL_OPTS="$ADDITIONAL_OPTS --force-group $force_group"
#fi
#if [ "$force_create_mode" != "" ] ; then
#	ADDITIONAL_OPTS="$ADDITIONAL_OPTS --force-create-mode $force_create_mode"
#fi
#if [ "$force_directory_mode" != "" ] ; then
#	ADDITIONAL_OPTS="$ADDITIONAL_OPTS --force-directory-mode $force_directory_mode"
#fi
#sudo /otpme-mounts/add_share.sh --share-name $share_name --share-root $share_root $ADDITIONAL_OPTS
