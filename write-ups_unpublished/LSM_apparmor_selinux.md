# Linux Security Modules
_2023-03, Eliot Roxbergh_

An overview of Linux hardening using Mandatory Access Control (MAC) and such.

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
Regardless if executed as a specific user, or even as root. \
However, a root user can change labels or policies to bypass the MAC.

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
2. With default block (whitelist) - it could be possible to pretend to be another file by overwriting it (inode for SELinux, path for AppArmor)¹, thereby gaining its access

Remember that, even a default allow is better than nothing.
We could, for instance, add a rule for the most "dangerous" programs: Firefox, Libreoffice, Thunderbird, and Docker comes to mind.
The idea is then that the security poilicy would protect the system even if one of these applications were to be
exploited by a 0day vulnerability. It would however not protect from attacks targeting other services, or if an attacker already has access to the system (e.g. logging in as a legitimate user).


¹ Surely it is harder to overwrite a file (inode) than a path (where we could create a file if it would not exist).

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
_"SELinux is a labeling system. Every process has a label. Every file, directory, or system object has a label.
Policy rules control access between labeled processes and labeled objects. Enforced by the kernel (LSM)."_

Default block, possible to change.

Tutorial: <https://wiki.gentoo.org/wiki/SELinux/Tutorials>

**Some terms:**
- Policy: Define types and what they should be able to do. \
Which objects have these types are then given to system objects (such as file or ports) via security contexts. \
To reiterate: the policy decides allowances for each type, and the security context defines which object has that type. 
- Context/Label: "Every process and object in the system has a context (also known as a label)" [2], this includes _type_ but also _user_, _role_, and an optional _sensitivity level_¹. This system object can be a file, port, or even X11, etc.\
For instance, the file 'file_contexts' holds regex to file(s) and the default context they should have. This also extends to binaries that are run, which creates a process in the related domain (_**TODO:** see "domain transition rules" which specifies this label should allow process to transition from its inherited domain into that of the rule, such as pop_t_)
- Boolean [1], an easy way to toggle certain parts of a policy at runtime. Thereby, it also shows common options that may be relevant for that policy.  \
Example: \
The boolean 'allow_ftpd_anon_write'[3] modifies the policy for ftpd to allow so-called anonymous users to write to disk. This is achieved with the _type_ 'public_content_rw_t' (to put it simply: like a special file permission), which is applied to files or directories that the anonymous user should have access to.
As the application (ftpd) itself is not aware of SELinux, SELinux bases this on the process and file _types_. _**TODO:** question, how does SELinux correctly identify that the FTP user writing is anonymous?_
- Domain:

¹ See Multi-Level Security (MLS) and Multi-Category Security (MCS): <https://selinuxproject.org/page/MLSStatements>, <https://selinuxproject.org/page/MultiCategorySecurity>, <https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers>

**Example of file types and names:**
- Booleans: `booleans.local` (persistent config of which booleans should be on)
- Policy: `policy.30` (all the compiled rules that will be used by SELinux system-wide, `.30` is simply the policy version). \
It may for instance be viewed with `seinfo policy.30  --all`
- Contexts: e.g. `file_contexts`, `file_context*`, (for _file_ system objects), this specifies the default contexts (labels) for different files and directories on disk.
Files may be deviate from this default (e.g. if it's simply moved there or was manually changed), it can optionally be restored with `restorecon`. \
Example line: `/var/ftp(/.*)?    system_u:object_r:ftpd_anon_rw_t:s0`

[1] - <https://wiki.gentoo.org/wiki/SELinux/Tutorials/Using_SELinux_booleans> \
[2] - <https://selinuxproject.org/page/BasicConcepts> \
[3] - <https://linux.die.net/man/8/ftpd_selinux>

#### AppArmor

AppArmor has default allow (!) [1], but it is possible to set a default block rule as well [2].

General: [3]

[1] - https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/AppArmorProfiles \
[2] - https://lists.ubuntu.com/archives/apparmor/2012-December/003241.html \
[3] - https://www.youtube.com/watch?v=PRZ59lxLlOY
