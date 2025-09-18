#!/bin/bash
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2

unset LANG

source /etc/otpme/otpme.conf

if [ "$PINENTRY" = "" ] ; then
	export PINENTRY="pinentry"
fi

# Offset lines (file header) to strip off decryption script from file.
SCRIPT_LINES_OFFSET="5"

TMP_DIR="/tmp/otpme-key-script.$RANDOM"
mkdir -p "$TMP_DIR"

if (exec < /dev/tty) ; then
	export TTY="/dev/tty"
fi

DISPLAY_FILE="$HOME/.display"
if [ -f $DISPLAY_FILE ] ; then
	export DISPLAY="$(cat $DISPLAY_FILE)"
fi

cleanup () {
	rm -rf "$TMP_DIR"
}
trap "cleanup" EXIT

set -e

BASENAME="$(basename "$0" | cut -d '.' -f 1)"
# Default encryption for data is AES.
ENC_TYPE="AES"
# Default encryption of AES keys is via RSA public key
AES_KEY_ENC="rsa"
CIPHER="aes-256-cbc"
ITERATIONS="5000000"

PASS_DECRYPT_SCRIPT='#!/bin/bash
SELF_LINES="$(head -n '$SCRIPT_LINES_OFFSET' "$0" | grep "#OTPME_SCRIPT_LINES:" | cut -d ":" -f 2)"
if [ "$SELF_LINES" = "" ] ; then
	echo "Found unknown file header." > /dev/stderr
	exit 1
fi
CIPHER="$(head -n '$SCRIPT_LINES_OFFSET' "$0" | grep "#CIPHER:" | cut -d ":" -f 2)"
if [ "$CIPHER" = "" ] ; then
	echo "File header is missing cipher." > /dev/stderr
	exit 1
fi
AES_KEY_ENCRYPTED="$(tail -n +$SELF_LINES "$0" | gzip -d | head -n1 | base64 -d)"
read -t 1 AES_PASS
if [ "$AES_PASS" = "" ] ; then
	echo -n "Password: " > /dev/tty
	read -s AES_PASS < /dev/tty
	echo > /dev/tty
fi
AES_KEY="$(echo "$AES_KEY_ENCRYPTED" | openssl $CIPHER -pbkdf2 -a -A -d -pass file:<(echo -n "$AES_PASS"))"
if [ "$?" != "0" ] ; then
	echo "Error while decypting AES key." 1>&2
	exit 1
fi
tail -n +$SELF_LINES "$0" | gzip -d | tail -n+2 | openssl $CIPHER -pbkdf2 -a -A -d -pass file:<(echo -n "$AES_KEY")
exit
#OTPME_DECRYPT_SCRIPT_END#
'

OTPME_DECRYPT_SCRIPT='#!/bin/bash
if [ "$1" = "" ] ; then
	OUTFILE="/dev/stdout"
else
	OUTFILE="$1"
fi
otpme-tool decrypt "$0" "$OUTFILE"
exit
#OTPME_DECRYPT_SCRIPT_END#
'


# Get command line options
get_opts () {
        # Get options
        if ! ARGS=`getopt -n $BASENAME -l help -l api -l auth-token -l rsa -l no-rsa -l salt-file -l key-enc -l use-gpg -l yubikey-hmac -l server-key -l force-pass -l no-self-decrypt u:b:h $*` ; then
                show_help
                return 1
        fi

        for I in $ARGS ; do
                case "$I" in
                        --use-gpg)
							shift
							GPG_ID="$1"
							GPG_KEY_ENCRYPTION="true"
							# Make sure we get an attribute for --use-gpg (and not an option)
							if [[ $GPG_ID == -* ]] ; then
								show_help
								return 1
							fi
							shift
                        ;;


                        --yubikey-hmac)
							shift
							YUBIKEY_SLOT="$1"
							AES_KEY_ENC="yubikey-hmac"
							# Make sure we get an yubikey slot as integer.
							if ! echo "$YUBIKEY_SLOT" | grep '^[0-9]*$' > /dev/null 2>&1 ; then
								show_help
								return 1
							fi
							shift
                        ;;


                        -u)
							shift
							ENC_USERNAME="$1"
							shift
                        ;;


                        -b)
							shift
							KEY_LEN="$1"
							shift
                        ;;


                        --server-key)
							KEY_MODE="server"
							shift
                        ;;


                        --rsa)
							USE_RSA="True"
							ENC_TYPE="RSA"
							shift
                        ;;


                        --salt-file)
							shift
							SALT_FILE="$1"
							if [ "$SALT_FILE" != "" ] ; then
								# FIXME: Is there a better way than using the SHA1 hash of the salt file as AES salt!?!
								PASSWORD_SALT="$(sha1sum "$SALT_FILE" | awk '{ print $1 }')"
							fi
							shift
                        ;;


                        --key-enc)
							shift
							KEY_ENC="$1"
							shift
                        ;;

                        --force-pass)
							FORCE_PASS="True"
							shift
                        ;;


                        --no-rsa)
							NO_RSA="True"
							shift
                        ;;


                        --no-self-decrypt)
							NO_SELF_DECRYPT_SCRIPT="True"
							shift
                        ;;


						--api)
							OTPME_OPTS="$OTPME_OPTS --api"
							shift
						;;

						--auth-token)
							shift
							AUTH_TOKEN="$1"
							OTPME_OPTS="--auth-token $AUTH_TOKEN $OTPME_OPTS"
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

	if [ "$NO_RSA" != "" ] && [ "$ENC_USERNAME" != "" ] ; then
		show_help
		return 1
	fi

	if [ "$NO_RSA" != "" ] && [ "$USE_RSA" != "" ] ; then
		show_help
		return 1
	fi

	# Make sure --key-enc is preferred over --use-gpg.
	if [ "$KEY_ENC" != "" ] ; then
		AES_KEY_ENC="$KEY_ENC"
	fi

	# Make sure we use AES encryption with passphrase when --force-pass is given.
	if [ "$FORCE_PASS" != "" ] ; then
		AES_KEY_ENC="aes"
	fi

	# Make sure we disable RSA encryption of AES keys.
	if [ "$NO_RSA" != "" ] ; then
		if [ "$AES_KEY_ENC" = "rsa" ] ; then
			AES_KEY_ENC="aes"
		fi
	fi

	COUNT="0"
	while [ "$1" != "" ] ; do
		PARAMETERS[$COUNT]="$1"
		shift
		COUNT="$[$COUNT+1]"
	done
}

show_help () {
	echo "Usage: $BASENAME [sign|verify|encrypt|decrypt|rsa_encrypt|rsa_decrypt] [-u username] [--help]"
	echo
	echo "Commands:"
	echo "	gen_keys					Generate users RSA key pair"
	echo "	gen_csr						Generate CSR"
	echo "	change_key_pass				Change passphrase of users private key"
	echo "	encrypt_key					Encrypt private key from stdin and write private key + public key to stdout"
	echo "	export_key					Export users private key unencrypted"
	echo "	sign <file> <sig_file>		Create signature file for <file>"
	echo "	verify <sig_file> <file>	Verify signature of <file>"
	echo "	encrypt <file> <enc_file>	Encrypt <file> and write it to <enc_file>"
	echo "	decrypt <enc_file> <file>	Decrypt <enc_file> and write it to <file>"
	echo "	rsa_encrypt					Encrypt <stdin> and write it to <stdout>"
	echo "	rsa_decrypt 				Decrypt <stdin> and write it to <stdout>"
	echo
	echo "Options:"
	echo "	-u <username>				Encrypt AES key of encrypted file with RSA public key of <username>"
	echo "	-b <bit>					Generate RSA key (gen_keys) of len <bit>"
	echo "	--server-key				Users RSA private key is kept on server"
	echo "	--rsa						Encrypt file with RSA public directly (file size limited to size of key)"
	echo "	--no-rsa					Disable use of RSA public keys for encryption of AES keys."
	echo "	--salt-file <file>			Use <file> as salt for AES encryption"
	echo "	--key-enc <rsa|aes|gpg>		Force encryption of AES keys with the given encrytion type (e.g. gpg)"
	echo "	--use-gpg <id>				Use given GPG key (e.g. to en/decrypt RSA private key)"
	echo "	--yubikey-hmac <slot>		Use yubikey in HMAC challenge/response mode to derive AES passphrase."
	echo "	--no-self-decrypt			Do not add self decryption script to encrypted file."
}

message () {
	echo "$*"
}

error_message () {
	echo "$*" 1>&2
}

tty_message () {
	if [ "$TTY" == "" ] ; then
		return
	fi
	echo "$*" > "$TTY"
}

get_public_key () {
	if [ "$1" = "" ] ; then
		local USERNAME="$_OTPME_KEYSCRIPT_USER"
	else
		local USERNAME="$1"
	fi
	if [ "$USERNAME" = "$_OTPME_KEYSCRIPT_USER" ] ; then
		if [ "$_OTPME_KEYSCRIPT_PUBLIC_KEY" != "" ] ; then
			echo "$_OTPME_KEYSCRIPT_PUBLIC_KEY"
			return
		fi
	fi
	tty_message "Loading public key: $USERNAME"
	if ! PUBLIC_KEY="$(otpme-user $OTPME_OPTS dump_key "$USERNAME")" ; then
		tty_message "Unable to load public key: $USERNAME"
		exit 1
	fi

	echo "$PUBLIC_KEY" | base64 -d
}

dump_private_key () {
	if [ "$_OTPME_KEYSCRIPT_PRIVATE_KEY" != "" ] ; then
		echo "$_OTPME_KEYSCRIPT_PRIVATE_KEY"
		return
	fi
	tty_message "Loading private key..."
	PRIVATE_KEY="$(otpme-user $OTPME_OPTS dump_key -p "$_OTPME_KEYSCRIPT_USER")"
	echo $PRIVATE_KEY
}

get_private_key () {
	if ! PRIVATE_KEY="$(dump_private_key)" ; then
		return 1
	fi
	echo "$PRIVATE_KEY" | base64 -d | decrypt_key
}

yk_derive_aes_key () {
	local AES_PASS="$1"
	# Get AES passphrase via HMAC response from yubikey.
	if ! HMAC_AES_PASS="$(ykchalresp -$YUBIKEY_SLOT "$AES_PASS")" ; then
		return 1
	fi
	echo "$HMAC_AES_PASS"
}

check_gpg_id () {
	if ! GPG_OUT="$(gpg2 --list-keys -a "$GPG_ID" 2>&1)" ; then
		echo "Unable to use GPG key: $GPG_OUT" > /dev/stderr
		return 1
	fi
}

gpg_encrypt () {
	if ! check_gpg_id ; then
		return 1
	fi
	TMP_FILE="$TMP_DIR/$RANDOM".tmp
	gpg2 --output - --encrypt -r "$GPG_ID" /dev/stdin 2> "$TMP_FILE"
	EXIT="$?"
	if [ "$EXIT" != "0" ] ; then
		cat "$TMP_FILE" > /dev/stderr
		rm "$TMP_FILE"
		return $EXIT
	else
		rm "$TMP_FILE"
		return 0
	fi
}

gpg_decrypt () {
	if ! check_gpg_id ; then
		return 1
	fi
	TMP_FILE="$TMP_DIR/$RANDOM".tmp
	#gpg2 -vvv --output - --decrypt -r "$GPG_ID" /dev/stdin 2> "$TMP_FILE"
	gpg2 -vvv --output - --decrypt /dev/stdin 2> "$TMP_FILE"
	EXIT="$?"
	if [ "$EXIT" != "0" ] ; then
		cat "$TMP_FILE" > /dev/stderr
		rm "$TMP_FILE"
		return $EXIT
	else
		rm "$TMP_FILE"
		return 0
	fi
}

aes_encrypt () {
	if [ "$AES_PASS" = "" ] ; then
		while true ; do
			NEW_PASS1="$(read_pass_from_tty "New password: ")"
			if [ "$NEW_PASS1" = "" ] ; then
				echo "Got empty password." > /dev/stderr
				return 1
			fi
			NEW_PASS2="$(read_pass_from_tty "Confirm password: ")"
			if [ "$NEW_PASS1" != "$NEW_PASS2" ] ; then
				tty_message "Passwords do not match."
				continue
			fi
			AES_PASS="$NEW_PASS1"
			break
		done
	fi

	# Get AES passphrase via HMAC response from yubikey if requested.
	if [ "$AES_KEY_ENC" = "yubikey-hmac" ] ; then
		if ! AES_PASS="$(yk_derive_aes_key "$AES_PASS")" ; then
			return 1
		fi
	fi

	cat | openssl $CIPHER -pbkdf2 -salt -iter $ITERATIONS -a -A -pass file:<(echo -n "$AES_PASS") | base64 -w 0
	if [ "${PIPESTATUS[1]}" != "0" ] ; then
		echo "Error while doing AES encryption." 1>&2
		return 1
	fi
}

aes_decrypt () {
	if [ "$AES_PASS" = "" ] ; then
		AES_PASS="$(read_pass_from_tty "Password: ")"
	fi

	# Get AES passphrase via HMAC response from yubikey if requested.
	if [ "$AES_KEY_ENC" = "yubikey-hmac" ] ; then
		if ! AES_PASS="$(yk_derive_aes_key "$AES_PASS")" ; then
			return 1
		fi
	fi

	cat | openssl $CIPHER -pbkdf2 -salt -iter $ITERATIONS -a -A -d -pass file:<(echo -n "$PASSWORD_SALT$AES_PASS")
	if [ "${PIPESTATUS[1]}" != "0" ] ; then
		echo "Error while doing AES decryption." 1>&2
		return 1
	fi
}

encrypt_key () {
	if [ "$GPG_KEY_ENCRYPTION" ] ; then
		gpg_encrypt | base64 -w 0
		return "${PIPESTATUS[0]}"
	else
		AES_PASS="$_OTPME_KEYSCRIPT_KEY_PASS"
		aes_encrypt
		RETURN="$?"
		unset AES_PASS
		return "$RETURN"
	fi
}

decrypt_key () {
	if [ "$GPG_KEY_ENCRYPTION" ] ; then
		gpg_decrypt
	else
		AES_PASS="$_OTPME_KEYSCRIPT_KEY_PASS"
		aes_decrypt
		RETURN="$?"
		unset AES_PASS
		return "$RETURN"
	fi
}

read_pass_from_tty () {
	if [ "$1" = "" ] ; then
		PROMPT="Password: "
	else
		PROMPT="$1"
	fi
	if [ "$GPG_TTY" = "" ] ; then
		GPG_TTY="$(otpme-tool get_tty)"
	fi
	echo -e "SETDESC Private key password for command $COMMAND\nSETPROMPT $PROMPT:\nGETPIN\n" | $PINENTRY -T "$GPG_TTY" | grep "^D " | cut -d' ' -f2-
	#echo -n "$PROMPT" > /dev/tty
	#read -s PASSWORD < /dev/tty
	#echo > /dev/tty
	#echo "$PASSWORD"
}

create_file_header () {
	KEY_ENC_TYPE="$AES_KEY_ENC"
	if [ "$NO_SELF_DECRYPT_SCRIPT" != "" ] ; then
		echo "#ENC_TYPE:$ENC_TYPE"
		echo "#ENC_USERNAME:$ENC_USERNAME"
		echo "#CIPHER:$CIPHER"
		echo "#KEY_ENC_TYPE:$KEY_ENC_TYPE"
		echo "#OTPME_SCRIPT_LINES:0"
		return
	fi
	if [ "$ENC_TYPE" = "AES" ] && [ "$AES_KEY_ENC" = "aes" ] ; then
		local DECRYPT_SCRIPT="$PASS_DECRYPT_SCRIPT"
	else
		local DECRYPT_SCRIPT="$OTPME_DECRYPT_SCRIPT"
	fi
	local SCRIPT_LINES="$(echo -en "$DECRYPT_SCRIPT" | wc -l)"
	local SCRIPT_LINES="$[$SCRIPT_LINES+$SCRIPT_LINES_OFFSET]"
	echo "#ENC_TYPE:$ENC_TYPE"
	echo "#ENC_USERNAME:$ENC_USERNAME"
	echo "#CIPHER:$CIPHER"
	echo "#KEY_ENC_TYPE:$KEY_ENC_TYPE"
	echo "#OTPME_SCRIPT_LINES:$SCRIPT_LINES"
	echo -en "$DECRYPT_SCRIPT"
}

handle_file_type () {
	# If we found the ENC_TYPE parameter in the first line this file does not
	# contain a decryption script.
	read LINE1
	ENC_TYPE="$(echo "$LINE1" | grep "#ENC_TYPE:" | cut -d ":" -f 2)"
	# If we found no header we assume RSA encrypted data.
	if [ "$ENC_TYPE" = "" ] ; then
		echo "RSA"
		# Pass first line (non-header) to decrypt_file()
		echo "$LINE1"
		cat
		return
	fi
	# Get ENC_USERNAME from file header. This may be empty if no ENC_USERNAME was given.
	read LINE2
	ENC_USERNAME="$(echo "$LINE2" | grep "#ENC_USERNAME:" | cut -d ":" -f 2)"
	# Get AES cipher from file header.
	read LINE3
	CIPHER="$(echo "$LINE3" | grep "#CIPHER:" | cut -d ":" -f 2)"
	if [ "$CIPHER" = "" ] ; then
		echo "File header is missing cipher. $LINE3" > /dev/stderr
		return 1
	fi
	# Get key encryption type (e.g. AES key encrypted with passphrase)
	read LINE4
	local KEY_ENC_TYPE="$(echo "$LINE4" | grep "#KEY_ENC_TYPE:" | cut -d ":" -f 2)"
	if [ "$KEY_ENC_TYPE" = "" ] ; then
		echo "Found unknown file header: $LINE4" > /dev/stderr
		return 1
	fi
	# Get length of self decryption script.
	read LINE5
	local SCRIPT_LINES="$(echo "$LINE5" | grep "#OTPME_SCRIPT_LINES:" | cut -d ":" -f 2)"
	if [ "$SCRIPT_LINES" = "" ] ; then
		echo "Found unknown file header: $LINE5" > /dev/stderr
		return 1
	fi
	# Skip all lines of a possible self decryption script.
	if [ "$SCRIPT_LINES" -gt 0 ] ; then
		local SCRIPT_LINES="$[$SCRIPT_LINES-$SCRIPT_LINES_OFFSET]"
		# Skip DECRYPT_SCRIPT lines we decrypting via otpme-tool.
		for i in $(seq 1 1 $SCRIPT_LINES) ; do
			read LINE
		done
	fi
	# Pass on cipher to decrypt_file()
	echo "$ENC_TYPE"
	echo "$CIPHER"
	echo "$KEY_ENC_TYPE"
	gzip -d
}


decrypt_file () {
	# Get encryption type from handle_file_type()
	read ENC_TYPE
	OUTFILE="$1"
	# Handle AES encrypted data.
	if [ "$ENC_TYPE" = "AES" ] ; then
		# Get AES stuff from handle_file_type()
		read CIPHER
		read KEY_ENC_TYPE
		read AES_KEY_ENCRYPTED
		export CIPHER
		export KEY_ENC_TYPE
		# Handle GPG encrypted AES key.
		if [ "$KEY_ENC_TYPE" = "gpg" ] ; then
			AES_KEY="$(echo "$AES_KEY_ENCRYPTED" | base64 -d | gpg_decrypt)"
		fi
		# Handle passphrase encrypted AES key.
		if [ "$KEY_ENC_TYPE" = "aes" ] ; then
			AES_PASS="$_OTPME_KEYSCRIPT_AES_PASS"
			AES_KEY="$(echo "$AES_KEY_ENCRYPTED" | base64 -d | aes_decrypt)"
			unset AES_PASS
		fi
		# Handle RSA encrypted AES key.
		if [ "$KEY_ENC_TYPE" = "rsa" ] ; then
			if [ "$KEY_MODE" = "server" ] ; then
				if [ "$_OTPME_KEYSCRIPT_KEY_PASS" = "" ] ; then
					#if ! AES_KEY="$(otpme-user $OTPME_OPTS decrypt --data "$AES_KEY_ENCRYPTED" "$_OTPME_KEYSCRIPT_USER" | base64 -d)" ; then
					if ! AES_KEY="$(echo -n "$AES_KEY_ENCRYPTED" | otpme-user $OTPME_OPTS decrypt --stdin-data "$_OTPME_KEYSCRIPT_USER" | base64 -d)" ; then
						return 1
					fi
				else
					if ! AES_KEY="$(echo "$_OTPME_KEYSCRIPT_KEY_PASS" | $(which otpme-user) $OTPME_OPTS decrypt --data "$AES_KEY_ENCRYPTED" --stdin-pass "$_OTPME_KEYSCRIPT_USER" | base64 -d)" ; then
						return 1
					fi
				fi
			else
				PRIVATE_KEY="$(get_private_key)"
				AES_KEY="$(echo "$AES_KEY_ENCRYPTED" | base64 -d | openssl pkeyutl -decrypt -inkey <(echo -n "$PRIVATE_KEY") -in /dev/stdin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256)"
			fi
		fi
		# Finally decrypt AES data.
		base64 -d | openssl enc -d -$CIPHER -salt -pbkdf2 -in /dev/stdin -pass file:<(echo -n "$AES_KEY") > "$OUTFILE"
	fi

	# Handle RSA encrypted data.
	if [ "$ENC_TYPE" = "RSA" ] ; then
		if [ "$KEY_MODE" = "server" ] ; then
			RSA_DATA="$(cat)"
			if [ "$_OTPME_KEYSCRIPT_KEY_PASS" = "" ] ; then
				#otpme-user $OTPME_OPTS decrypt --data "$RSA_DATA" "$_OTPME_KEYSCRIPT_USER"
				echo -n "$RSA_DATA" | otpme-user $OTPME_OPTS decrypt --stdin-data "$_OTPME_KEYSCRIPT_USER"
			else
				echo "$_OTPME_KEYSCRIPT_KEY_PASS" | $(which otpme-user) $OTPME_OPTS decrypt --data "$RSA_DATA" --stdin-pass "$_OTPME_KEYSCRIPT_USER"
			fi
		else
			PRIVATE_KEY="$(get_private_key)"
			base64 -d | openssl pkeyutl -decrypt  -inkey <(echo -n "$PRIVATE_KEY") -in /dev/stdin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
		fi
	fi
}

# Get command
COMMAND="$1"
shift

if [ "$COMMAND" = "" ] ; then
	show_help
	return 1
fi

if ! get_opts "$@" ; then
	exit 1
fi

if [ "$KEY_MODE" = "" ] ; then
	KEY_MODE="$(otpme-user $OTPME_OPTS get_key_mode $_OTPME_KEYSCRIPT_USER)"
fi

case "$COMMAND" in
	export_key)
		get_private_key
	;;

	gen_keys)
		tty_message "Generating key ($KEY_LEN)..."
		if ! PRIVATE_KEY="$(openssl genrsa $KEY_LEN)" ; then
			echo "Error generating key." 1>&2
			exit 1
		fi
		if ! PRIVATE_KEY_ENC="$(echo "$PRIVATE_KEY" | encrypt_key)" ; then
			exit 1
		fi
		if ! PUBLIC_KEY="$(echo "$PRIVATE_KEY" | openssl rsa -pubout -in /dev/stdin)" ; then
			echo "Error extacting public key." 1>&2
			exit 1
		fi
		PUBLIC_KEY_ENC="$(echo -n "$PUBLIC_KEY" | base64 -w 0)"
		echo "$PRIVATE_KEY_ENC" "$PUBLIC_KEY_ENC"
	;;

	gen_csr)
		PRIVATE_KEY="$(get_private_key)"
		CSR_SUBJECT="/C=DE/ST=NRW/L=Koeln/O=OTPme/OU=Development/CN=otpme.org"
		OPENSSL_CSR_CMD="openssl req -new -nodes -key /dev/stdin -subj "$CSR_SUBJECT""
		if ! CSR="$(echo "$PRIVATE_KEY" | $OPENSSL_CSR_CMD)" ; then
			exit 1
		fi
		if [ "$CSR" = "" ] ; then
			exit 1
		fi
		echo "$CSR"
	;;

	encrypt_key)
		PRIVATE_KEY="$(cat -)"
		if ! PRIVATE_KEY_ENC="$(echo "$PRIVATE_KEY" | encrypt_key)" ; then
			exit 1
		fi
		if ! PUBLIC_KEY="$(echo "$PRIVATE_KEY" | openssl rsa -pubout -in /dev/stdin)" ; then
			echo "Error extacting public key." 1>&2
			exit 1
		fi
		PUBLIC_KEY_ENC="$(echo -n "$PUBLIC_KEY" | base64 -w 0)"
		echo "$PRIVATE_KEY_ENC" "$PUBLIC_KEY_ENC"
	;;

	change_key_pass)
		if [ "$GPG_KEY_ENCRYPTION" != "" ] ; then
			echo "Cannot change key passphrase in GPG mode." > /dev/stderr
			exit 1
		fi
		PRIVATE_KEY="$(get_private_key)"
		_OTPME_KEYSCRIPT_KEY_PASS="$_OTPME_KEYSCRIPT_KEY_PASS_NEW"
		if PRIVATE_KEY_ENC="$(echo "$PRIVATE_KEY" | encrypt_key)" ; then
			echo "$PRIVATE_KEY_ENC"
		else
			exit 1
		fi
	;;

	rsa_encrypt)
		if [ "$ENC_USERNAME" = "" ] ; then
			PUBLIC_KEY="$(get_public_key)"
		else
			PUBLIC_KEY="$(get_public_key "$ENC_USERNAME")"
		fi
		openssl pkeyutl -encrypt -pubin -inkey <(echo -n "$PUBLIC_KEY") -in /dev/stdin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 | base64 -w 0
		exit $?
	;;

	rsa_decrypt)
		if [ "$KEY_MODE" = "server" ] ; then
			#DATA="$(cat -)"
			#otpme-user $OTPME_OPTS decrypt --data "$DATA" "$_OTPME_KEYSCRIPT_USER" | base64 -d
			cat - | otpme-user $OTPME_OPTS decrypt --stdin-data "$_OTPME_KEYSCRIPT_USER" | base64 -d
		else
			PRIVATE_KEY="$(get_private_key)"
			cat - | base64 -d | openssl pkeyutl -decrypt -inkey <(echo -n "$PRIVATE_KEY") -in /dev/stdin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
		fi
		exit $?
	;;

	sign)
		FILE="${PARAMETERS[0]}"
		OUTFILE="${PARAMETERS[1]}"
		if [ "$OUTFILE" = "-" ] ; then
			OUTFILE="/dev/stdout"
		fi
		if [ ! -e "$FILE" ] ; then
			error_message "$BASENAME: No such file or directory: $FILE"
			exit 1
		fi
		if [ "$KEY_MODE" = "server" ] ; then
			SHA256_SUM="$(sha256sum "$FILE" | awk '{ print $1 }')"
			if [ "$_OTPME_KEYSCRIPT_KEY_PASS" = "" ] ; then
				if ! SIGNATURE="$(otpme-user $OTPME_OPTS sign_data --digest "$SHA256_SUM" "$_OTPME_KEYSCRIPT_USER")" ; then
					exit 1
				fi
			else
				if ! SIGNATURE="$(echo "$_OTPME_KEYSCRIPT_KEY_PASS" | $(which otpme-user) $OTPME_OPTS sign_data --digest "$SHA256_SUM" --stdin-pass "$_OTPME_KEYSCRIPT_USER")" ; then
					exit 1
				fi
			fi
		else
			PRIVATE_KEY="$(get_private_key)"
			# Sign PKCS1_v1_5
			#OPENSSL_SIGN_CMD="openssl dgst -sha256 -sign /dev/stdin "$FILE""
			# Sign PKCS1_PSS
			OPENSSL_SIGN_CMD="openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-2 -sign /dev/stdin "$FILE""
			if ! SIGNATURE="$(echo "$PRIVATE_KEY" | $OPENSSL_SIGN_CMD | base64 -w 0)" ;  then
				exit 1
			fi
		fi
		if [ "$SIGNATURE" = "" ] ; then
			exit 1
		fi
		(echo 'USERNAME="'$_OTPME_KEYSCRIPT_USER'"';echo 'SIGNATURE="'$SIGNATURE'"')  > "$OUTFILE"
	;;

	verify)
		SIG_FILE="${PARAMETERS[0]}"
		FILE="${PARAMETERS[1]}"
		TMP_FILE="$TMP_DIR/$RANDOM".tmp
		if [ "$FILE" = "" ] || [ "$SIG_FILE" = "" ] ; then
			error_message "Usage: $BASENAME verify <sig_file> <file>"
			exit 1
		fi

		if [ ! -e "$FILE" ] ; then
			error_message "$BASENAME: No such file or directory: $FILE"
			exit 1
		fi

		if [ ! -e "$SIG_FILE" ] ; then
			error_message "$BASENAME: No such file or directory: $SIG_FILE"
			exit 1
		fi

		SIGNER="$(cat "$SIG_FILE" | grep "^USERNAME=" | cut -d '"' -f 2)"
		if [ "$SIGNER" == "" ] ; then
			echo "Unable to get signer from signature file: $SIG_FILE" > /dev/stderr
			exit 1
		fi
		SIGNER_PUBLIC_KEY="$(otpme-user $OTPME_OPTS dump_key "$SIGNER" | base64 -d)"
		cat "$SIG_FILE" | grep "^SIGNATURE=" | cut -d '"' -f 2 | base64 -d > "$TMP_FILE"
		# Sign PKCS1_v1_5
		#OPENSSL_VERIFY_CMD="openssl dgst -sha256 -verify /dev/stdin -signature "$TMP_FILE" "$FILE""
		# Sign PKCS1_PSS
		OPENSSL_VERIFY_CMD="openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-2 -verify /dev/stdin -signature "$TMP_FILE" "$FILE""
		rm "$TMP_FILE"
		echo "$SIGNER_PUBLIC_KEY" | $OPENSSL_VERIFY_CMD
	;;

	encrypt)
		FILE="${PARAMETERS[0]}"
		OUTFILE="${PARAMETERS[1]}"
		if [ "$OUTFILE" = "-" ] ; then
			OUTFILE="/dev/stdout"
		fi
		if [ "$FILE" = "" ] ; then
			error_message "Usage: $BASENAME encrypt <file>"
			exit 1
		fi

		if [ ! -e "$FILE" ] ; then
			error_message "$BASENAME: No such file or directory: $FILE"
			exit 1
		fi

		if [ "$AES_KEY_ENC" = "rsa" ] ; then
			if [ "$ENC_USERNAME" = "" ] ; then
				PUBLIC_KEY="$(get_public_key)"
			else
				PUBLIC_KEY="$(get_public_key "$ENC_USERNAME")"
			fi
			if [ "$ENC_TYPE" = "RSA" ] ; then
				cat "$FILE" | openssl pkeyutl -encrypt -pubin -inkey <(echo -n "$PUBLIC_KEY") -in /dev/stdin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 | base64 -w 0 > "$OUTFILE"
				# We need a newline to get the first line with bash's read builtin in handle_file_type()
				echo -en "\n" >> "$OUTFILE"
				exit $?
			else
				AES_KEY="$(openssl rand -base64 32)"
				AES_KEY_ENCRYPTED="$(echo "$AES_KEY" | openssl pkeyutl -encrypt -pubin -inkey <(echo -n "$PUBLIC_KEY") -in /dev/stdin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 | base64 -w 0)"
			fi
		else
			AES_KEY="$(openssl rand -base64 32)"
			# Do not encrypt AES key with GPG if we got a AES passphrase via $_OTPME_KEYSCRIPT_AES_PASS
			if [ "$AES_KEY_ENC" = "gpg" ] ; then
				AES_KEY_ENCRYPTED="$(echo -n "$AES_KEY" | gpg_encrypt | base64 -w 0)"
			else
				# Preset possible AES passphrase from $_OTPME_KEYSCRIPT_AES_PASS
				AES_PASS="$_OTPME_KEYSCRIPT_AES_PASS"
				AES_KEY_ENCRYPTED="$(echo -n "$AES_KEY" | aes_encrypt)"
				unset AES_PASS
			fi
		fi

		create_file_header > "$OUTFILE"
		(echo "$AES_KEY_ENCRYPTED";cat "$FILE" | openssl enc -$CIPHER -salt -pbkdf2 -pass file:<(echo -n "$AES_KEY") | base64 -w 0) | gzip -f >> "$OUTFILE"
	;;

	decrypt)
		FILE="${PARAMETERS[0]}"
		OUTFILE="${PARAMETERS[1]}"
		if [ "$OUTFILE" = "-" ] ; then
			OUTFILE="/dev/stdout"
		fi
		if [ "$FILE" = "" ] ; then
			error_message "Usage: $BASENAME decrypt <file>"
			exit 1
		fi

		if [ ! -e "$FILE" ] ; then
			error_message "$BASENAME: No such file or directory: $FILE"
			exit 1
		fi

		cat "$FILE" | handle_file_type | decrypt_file "$OUTFILE"
	;;

	*)
		# Print to stderr to be catched by otpme.
		echo "Unknown command: $COMMAND" 1>&2
		echo "Usage: $BASENAME [ gen [key_len] | encrypt_key | decrypt_key ]"
		exit 1
	;;
esac
