#!/bin/bash

FILE="$1"
#MIN_LEN="3"
#MAX_LEN="16"

if file "$FILE" | grep -i "utf-8" > /dev/null 2>&1 ; then
	FILE_ENCODING="UTF-8"
fi

change_encoding () {
	if [ "$FILE_ENCODING" != "UTF-8" ] ; then
		iconv -f ISO-8859-15 -t utf-8
	else
		cat
	fi
}

cat "$FILE" | change_encoding \
	| awk '{ print $1 }' \
	| tr 'ü' 'ue' \
	| tr 'Ü' 'Ue' \
	| tr 'ö' 'oe' \
	| tr 'Ö' 'Oe' \
	| tr 'ä' 'ae' \
	| tr 'Ä' 'Ae' \
	| tr 'ß' 'ss' \
	| grep '^[0-9a-zA-Z ]*$' \
	| tr '[:upper:]' '[:lower:]'
	#| grep -o -w "\w\{$MIN_LEN,$MAX_LEN\}"
