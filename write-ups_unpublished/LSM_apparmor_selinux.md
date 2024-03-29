# Linux Security Modules
_2023-03, Eliot Roxbergh_

An overview of Linux hardening using Mandatory Access Control and such.

## See Also

**File access control (ACL)** \
Try to limit file permissions, and for more advanced usage see facl. \
setfacl, .. [1]

**Logs:** \
auditd (summary /w aureport)

**More:** \
Firewall (often disabled by default): ufw/firewalld = frontends to iptables/nftables. \
(Local) intrusion detection (database, check if files on system modified): AIDE, rkhunter \
Audit system config? e.g. OpenSCAP ? ......


[1] - https://www.redhat.com/sysadmin/linux-access-control-lists


## Linux Security Modules /w MAC

Linux Security Modules (e.g. SELinux, AppArmor) can enable further checks (hooks) before a syscall can be performed, blocking unusual/undesirable behavior - even by the root user. That is, it is a policy set by the administrator, as oppose to rules set by individual users on the system (such as file permissions²), and applies on a per process basis (process centric). Note, LSM has nothing to do with loadable kernel modules [1].

Mainly, LSM provides additional security through MAC extensions such as SELinux and AppArmor.
For other types of LSMs see in particular LoadPin and Yama [1]. Multiple LSMs can be used at once [2].
This article will only focus on MAC type LSMs.

For MAC LSMs (such as SELinux and AppArmor), the main idea is that each executable file¹ (process) has a unique security policy of what it should be allowed to do.
Such as, read/write access to specific files, low level network access (e.g. ping), etc. etc.
Regardless if executed as a specific user, or even as root.

For an introduction of LSMs available, see [1].


¹ Or collection of similar programs/types? \
² Commonly used acronyms; **DAC** (owner centric) includes Linux file permissions, that is, owners can change privileges at their own _discretion_. While **MAC** (e.g. process centric) is closer to zero-trust and is _mandatory_ in the system, which includes SELinux and AppArmor discussed here.


[1] - https://www.kernel.org/doc/html/latest/admin-guide/LSM/ \
[2] - https://lwn.net/Articles/804906/

### Policies
Creating policies is time consuming, but many applications already have policies ready to apply
(which may of course still cause problems if you use the program in advanced ways, and would then need to be configured further).
To create your own policy, it is also possible to run the program first in a permissive mode and then automatically
allow all behaviors seen in this clean run - as is supported by AppArmor/SELinux tools.
For more complex programs, I assume, this would need ongoing work however.

### Executable Files

As I remember SELinux goes by file inode, and AppArmor by the path, of the executable.
The remaining files, which does not have an explicit policy,
can either be default block or default allow depending on the configuration

Here we directly notice two potential issues;
1. AppArmor has default allow (blacklist) - so by moving a file it gains full access.
2. With default block (whitelist) - it could be possible to pretend to be another file by overwriting it (inode for SELinux¹, path for AppArmor), thereby gaining its access

Remember that, even a default allow is better than nothing.
We could, for instance, add a rule for the most "dangerous" programs: Firefox, Libreoffice, Thunderbird, and Docker comes to mind.
The idea is then that the security poilicy would protect the system even if one of these applications were to be
exploited by a 0day vulnerability. It would however not protect from attacks targeting other services, or if an attacker already has access to the system (e.g. logging in as a legitimate user).


¹ Is it harder to overwrite an inode than path?

### Practical

Show active processes, list and sort by security label (here AppArmor), example, \
`ps axo pid,euser,ruser,suser,fuser,f,comm,exe,label --sort=+label`
```
    PID EUSER    RUSER    SUSER    FUSER    F COMMAND         EXE   LABEL
2211266 root     root     root     root     4 cups-browsed    -     /usr/sbin/cups-browsed (enforce)
2211263 root     root     root     root     4 cupsd           -     /usr/sbin/cupsd (enforce)
   2028 root     root     root     root     4 libvirtd        -     libvirtd (enforce)
```


### Details

#### SELinux

Default block

#### AppArmor

AppArmor has default allow (!) [1], but it is possible to set a default block rule as well [2].

General: [3]

[1] - https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/AppArmorProfiles \
[2] - https://lists.ubuntu.com/archives/apparmor/2012-December/003241.html \
[3] - https://www.youtube.com/watch?v=PRZ59lxLlOY
