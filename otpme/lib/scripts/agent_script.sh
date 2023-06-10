#!/bin/bash
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2

unset LANG
BASENAME="$(basename "$0" | cut -d '.' -f 1)"

if [ "$SSH_AGENT_NAME" = "" ] ; then
	export SSH_AGENT_NAME="ssh-agent"
fi


# Get command line options
get_opts () {
        # Get options
        if ! ARGS=$(getopt -n $BASENAME -l help -l gpg-agent -l gpg-smartcard h $*) ; then
                show_help
                return 1
        fi

        for I in $ARGS ; do
                case "$I" in
                        --gpg-smartcard)
				# We need to export all option variables to make
				# them available when calling ourselves (e.g. via
				# $0 status)
                                export USE_GPG_SMARTCARD="True"
				# This option implies --gpg-agent
				export SSH_AGENT_NAME="gpg-agent"
                                shift
                        ;;

                        --gpg-agent)
				export SSH_AGENT_NAME="gpg-agent"
                                shift
			;;

                        -h)
                                shift
                                show_help
                                return 1
                        ;;

                        --help)
                                shift
                                show_help
                                return 1
                        ;;

			--)
				break
			;;
                esac
        done

	COUNT="0"
	while [ "$1" != "" ] ; do
		PARAMETERS[$COUNT]="$1"
		shift
		COUNT="$[$COUNT+1]"
	done

	# Get command (last parameter)
	if [ "$PARAMETERS" != "" ] ; then
		COMMAND="${PARAMETERS[$[COUNT-1]]}"
	fi
}

show_help () {
	echo "Usage: $BASENAME [sign|verify|encrypt|decrypt] [-u username] [--help]"
	echo
	echo "Commands:"
	echo "	start				Start SSH agent."
	echo "	stop				Stop SSH agent."
	echo "	restart				Restart SSH agent."
	echo "	status				Show SSH agent status."
	echo
	echo "Options:"
	echo "	--gpg-smartcard			Enable handling of gpg-agent when used with a smartcard."
}

message () {
	echo "$*"
}

error_message () {
	echo "$*" 1>&2
}

kill_pid () {
	local PID="$1"
	if [ "$PID" = "" ] ; then
		return
	fi

	local COUNT="0"
	local KILL_COUNT="3"
	while kill -0 "$PID" > /dev/null 2>&1 ; do
		if [ "$COUNT" -lt "$KILL_COUNT" ] ; then
			kill -SIGTERM "$PID"
		else
			echo "Warning: Process $PID did not terminate after sending SIGTERM $COUNT times."
			echo "Warning: Sending SIGKILL to PID $PID."
			kill -SIGKILL "$PID"
		fi
		COUNT="$[$COUNT+1]"
		sleep 1
	done
}

if ! get_opts "$@" ; then
	exit 1
fi

if [ "$COMMAND" = "" ] ; then
	show_help
	exit 1
fi

if [ "$OTPME_LOGIN_SESSION_DIR" = "" ] ; then
	echo "Cannot start SSH agent without OTPME_LOGIN_SESSION_DIR set." > /dev/stderr
	exit 1
fi

if [ "$OTPME_SSH_AGENT_VARS_FILE" = "" ] ; then
	echo "WARNING: SSH agent script got no OTPME_SSH_AGENT_VARS_FILE!" > /dev/stderr
	OTPME_SSH_AGENT_VARS_FILE="$OTPME_LOGIN_SESSION_DIR/.ssh_agent_vars"
fi


case $COMMAND in
	start)
		if $0 status > /dev/null 2>&1 ; then
			echo "SSH agent already running."
		else
			if [ "$SSH_AGENT_NAME" == "gpg-agent" ] ; then
				AGENT_OUT="$(gpg-agent --daemon --enable-ssh-support --log-file ~/.gnupg/gpg-agent.log --pinentry-program $OTPME_BIN_DIR/otpme-pinentry)"
			else
				AGENT_OUT="$(ssh-agent)"
			fi
			SSH_AGENT_SOCKET_PATH="$(echo "$AGENT_OUT" | grep "SSH_AUTH_SOCK" | cut -d '=' -f 2 | cut -d ';' -f 1)"
			SSH_AGENT_PID="$(echo "$AGENT_OUT" | grep "SSH_AGENT_PID" | cut -d '=' -f 2 | cut -d ';' -f 1)"

			# Newer gpg-agent versions (since ubuntu 16.04) do not output SSH_AGENT_PID.
			if [ "$SSH_AGENT_PID" = "" ] ; then
				if [ "$SSH_AGENT_NAME" == "gpg-agent" ] ; then
					SSH_AGENT_PID="$(pgrep -u "$USER" gpg-agent | tail -n1)"
				else
					SSH_AGENT_PID="$(pgrep -u "$USER" ssh-agent | tail -n1)"
				fi
			fi

			if [ "$OTPME_SSH_AGENT_SOCKET" = "" ] ; then
				SSH_AUTH_SOCK="$SSH_AGENT_SOCKET_PATH.$SSH_AGENT_PID"
			else
				SSH_AUTH_SOCK="$OTPME_SSH_AGENT_SOCKET"
			fi

			if [ "$OTPME_SSH_AGENT_SOCKET" != "" ] ; then
				OTPME_SSH_AGENT_SOCKET_DIR="$(dirname $OTPME_SSH_AGENT_SOCKET)"
				mkdir -p "$OTPME_SSH_AGENT_SOCKET_DIR"
				ln -sf $SSH_AGENT_SOCKET_PATH $OTPME_SSH_AGENT_SOCKET
			fi

			# Set ssh-agent variables.
			echo "SSH_AGENT_PID=$SSH_AGENT_PID; export SSH_AGENT_PID;" > "$OTPME_SSH_AGENT_VARS_FILE"
			echo "SSH_AUTH_SOCK=$SSH_AUTH_SOCK; export SSH_AUTH_SOCK;" >> "$OTPME_SSH_AGENT_VARS_FILE"
			echo "SSH_AGENT_NAME=$SSH_AGENT_NAME; export SSH_AGENT_NAME;" >> "$OTPME_SSH_AGENT_VARS_FILE"

			if [ "$SSH_AGENT_NAME" == "gpg-agent" ] ; then
				GPG_AGENT_SOCKET_PATH="$(echo "$AGENT_OUT" | grep "GPG_AGENT_INFO" | cut -d '=' -f 2 | cut -d ';' -f 1 | cut -d ':' -f 1)"
				GPG_AGENT_PID="$(echo "$AGENT_OUT" | grep "GPG_AGENT_INFO" | cut -d '=' -f 2 | cut -d ';' -f 1 | cut -d ':' -f 2-)"
				if [ "$OTPME_GPG_AGENT_SOCKET" = "" ] ; then
					GPG_AGENT_INFO="$GPG_AGENT_SOCKET_PATH:$GPG_AGENT_PID"
				else
					GPG_AGENT_INFO="$OTPME_GPG_AGENT_SOCKET:$GPG_AGENT_PID"
				fi

				if [ "$OTPME_GPG_AGENT_SOCKET" != "" ] ; then
					OTPME_GPG_AGENT_SOCKET_DIR="$(dirname $OTPME_GPG_AGENT_SOCKET)"
					mkdir -p "$OTPME_GPG_AGENT_SOCKET_DIR"
					ln -sf $GPG_AGENT_SOCKET_PATH $OTPME_GPG_AGENT_SOCKET
				fi
				# Set gpg-agent variable.
				echo "GPG_AGENT_INFO=$GPG_AGENT_INFO; export GPG_AGENT_INFO;" >> "$OTPME_SSH_AGENT_VARS_FILE"
			fi
		fi

		# Print agent variables to stdout.
		cat "$OTPME_SSH_AGENT_VARS_FILE"
	;;

	stop)
		if [ "$SSH_AGENT_NAME" == "gpg-agent" ] ; then
			if [ "$USE_GPG_SMARTCARD" = "" ] && [ -f "$OTPME_SSH_AGENT_VARS_FILE" ] ; then
				# When using gpg-agent without smartcard we kill only the
				# gpg-agent from our session.
				source "$OTPME_SSH_AGENT_VARS_FILE"
				AGENT_PIDS="$(pgrep -u "$USER" -f "$SSH_AGENT_NAME" | grep "^$SSH_AGENT_PID$")"
			else
				# When using gpg-agent with smartcard only one gpg-agent can
				# run at a time. So we kill all agents of the user.
				AGENT_PIDS="$(pgrep -u "$USER" "$SSH_AGENT_NAME")"
			fi
		else
			AGENT_PIDS="$(pgrep -u "$USER" "$SSH_AGENT_NAME")"
		fi

		# Kill agent PIDs.
		for AGENT_PID in $AGENT_PIDS ; do
			kill_pid $AGENT_PID
		done
	;;

	unlock)
		if $0 status > /dev/null 2>&1 ; then
			if [ "$SSH_AGENT_NAME" == "gpg-agent" ] ; then
				if [ "$USE_GPG_SMARTCARD" = "" ] ; then
					$0 restart
				else
					# When using gpg-agent with smartcard we have to make sure that the running agent
					# is from this session (e.g. DISPLAY must be set for pinentry to work).
					source "$OTPME_SSH_AGENT_VARS_FILE"
					if pgrep -f "$SSH_AGENT_NAME" -s "$SSH_AGENT_PID" > /dev/null 2>&1 ; then
						# When doing a screen unlock with a smartcard we do not kill gpg-agent to make
						# it re-ask the user for the smartcard PIN. Instead we instruct scdaemon to do
						# a reload which leads to re-asking for the PIN.
						while pgrep -u "$USER" scdaemon > /dev/null 2>&1 ; do
							# FIXME: "gpgconf --reload scdaemon" does not work GnuPG 2.0 because
							#	 of a bug and the suggested "gpg-connect-agent" command was
							#	 not working reliable so we kill scdaemon as a workaround.
							#	 But as stopping scdaemon via SIGTERM is much slower than
							#	 with SIGKILL, which is annoying when doing a screen unlock,
							#	 we use SIGKILL. This works very well at least with my yubikey.
							#	 If you run into any issues with this please file a bug report.
							# https://lists.gnupg.org/pipermail/gnupg-users/2015-September/054272.html
							pkill -9 -u "$USER" scdaemon > /dev/null 2>&1
						done
					else
						# If the found gpg-agent is not from this session restart it.
						$0 restart
					fi
				fi
			else
				# When using ssh-agent we just restart the agent.
				$0 restart
			fi
			# We always print agent vars from file because the
			# current environment variable may be outdated (e.g. in
			# case of a previous crashed gpg-agent)
			cat "$OTPME_SSH_AGENT_VARS_FILE"
		else
			$0 start
		fi
	;;

	restart)
			$0 stop
			$0 start
	;;

	status)
		if [ "$USE_GPG_SMARTCARD" = "" ] ; then
			# When using gpg-agent without smartcard we check only for the
			# gpg-agent from our session.
			source "$OTPME_SSH_AGENT_VARS_FILE"
			pgrep -f "$SSH_AGENT_NAME" -s "$SSH_AGENT_PID" > /dev/null 2>&1
			STATUS="$?"
		else
			# When using gpg-agent with smartcard only one gpg-agent can
			# run at a time. So we check for all agent processes of the user.
			pgrep -u "$USER" "$SSH_AGENT_NAME" > /dev/null 2>&1
			STATUS="$?"
		fi

		if [ "$STATUS" = "0" ] ; then
			echo "Running"
			exit 0
		else
			echo "Stopped"
			exit 1
		fi
	;;
esac
