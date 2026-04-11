#!/bin/bash
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2

unset LANG
BASENAME="$(basename "$0" | cut -d '.' -f 1)"
PINENTRY_BIN="$OTPME_BIN_DIR/otpme-pinentry"

if [ "$SSH_AGENT_NAME" = "" ] ; then
	export SSH_AGENT_NAME="ssh-agent"
fi

# Get command line options
get_opts () {
        # Get options
        if ! ARGS=$(getopt -n $BASENAME -l help -l pinentry -l gpg-agent -l gpg-smartcard -l yubikey-piv -l no-confirm h $*) ; then
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

                        --yubikey-piv)
							export ADD_YUBIKEY_PIV="true"
							shift
						;;

                        --no-confirm)
							export NO_CONFIRM="true"
							shift
						;;

                        --pinentry)
							shift
							export PINENTRY_BIN="$1"
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
	echo "	add_key				Add key (e.g. yubikey PIV) to ssh-agent."
	echo
	echo "Options:"
	echo "	--gpg-smartcard		Enable handling of gpg-agent when used with a smartcard."
	echo "	--yubikey-piv		Use yubikey PIV on ssh-add."
	echo "	--no-confirm		Dont confim ssh-agent key usage."
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

case $COMMAND in
	start)
		if $0 status > /dev/null 2>&1 ; then
			echo "SSH agent already running."
		else
			if [ "$SSH_AGENT_NAME" == "gpg-agent" ] ; then
				AGENT_OUT="$(gpg-agent --daemon --enable-ssh-support --log-file ~/.gnupg/gpg-agent.log --pinentry-program $PINENTRY_BIN)"
				AGENT_PID="$(pgrep -u "$USER" -f "$SSH_AGENT_NAME")"
				AGENT_OUT="$AGENT_OUT\nSSH_AGENT_PID=$AGENT_PID;export SSH_AGENT_PID"
			else
				#export SSH_ASKPASS=/usr/bin/ssh-askpass
				AGENT_OUT="$(ssh-agent)"
			fi
			echo -e "$AGENT_OUT"
		fi
	;;

	add_key)
		if [ "$ADD_YUBIKEY_PIV" = "true" ] ; then
			if [ "$PIN" = "" ] ; then
				echo "Please set PIN variable." > /dev/stderr
				exit 1
			fi
			PIN_SCRIPT="/tmp/pin-$RANDOM.sh"
			touch "$PIN_SCRIPT"
			chmod 700 "$PIN_SCRIPT"
			echo 'echo "$PIN"' > "$PIN_SCRIPT"
			KEY_CONFIRM_OPT="-c"
			if [ "$NO_CONFIRM" = "true" ] ; then
				KEY_CONFIRM_OPT=""
			fi
			SSH_ASKPASS=$PIN_SCRIPT SSH_ASKPASS_REQUIRE=force ssh-add $KEY_CONFIRM_OPT -s /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
			rm $PIN_SCRIPT
		fi
	;;

	stop)
		AGENT_PIDS="$(pgrep -u "$USER" -f "$SSH_AGENT_NAME")"
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
					if pgrep -f "$SSH_AGENT_NAME" -u "$USER" > /dev/null 2>&1 ; then
						# On screen unlock we must ensure gpg-agent will re-ask for the token pin.
						# There seem to be some ways to accomplish this:
						#   gpgconf --kill scdaemon
						#   gpg-connect-agent "SCD RESET" /bye
						#	gpg-connect-agent --no-autostart -S "$HOME/.gnupg/S.gpg-agent" "SCD RESET" /bye
						#	gpg-connect-agent --no-autostart -S "$HOME/.gnupg/S.gpg-agent" "reloadagent" /bye
						#	gpg-connect-agent --no-autostart -S "$HOME/.gnupg/S.gpg-agent" "SCD KILLSCD" /bye
						#	gpg-connect-agent --no-autostart -S "$HOME/.gnupg/S.gpg-agent" "CLEARPASSPHRASE --mode=normal *" /bye
						# All do not work for me. Maybe someone else can find out why.
						while pgrep -u "$USER" scdaemon > /dev/null 2>&1 ; do
							pkill -u "$USER" scdaemon > /dev/null 2>&1
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
			pgrep -f "$SSH_AGENT_NAME" -u "$USER" > /dev/null 2>&1
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
