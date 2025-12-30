## Introduction | why root
Fully compromising the host would allow us to capture traffic and access sensitive files, which may be used to further access within the environment. Additionally, if the Linux machine is domain joined, we can gain the NTLM hash and begin enumerating and attacking Active Directory.
## enumeration Methodology
|When you gain initial shell access to the host, it is important to check several key details.
- `OS Version`:Knowing the distribution (Ubuntu, Debian, FreeBSD, Fedora, SUSE, Red Hat, CentOS, etc.) will give you an idea of the types of tools that may be available

- `Kernel Version`: As with the OS version, there may be public exploits that target a vulnerability in a specific kernel version.
- `User Home Directories`: Are other user's home directories accessible? User home folders may also contain SSH keys that can be used to access other systems or scripts and configuration files containing credentials.
- `Sudo Privileges`: Can the user run any commands either as another user or as root? look for `nopasswd` meaning it lets u run commands without prompt for password.

- `Running Services`: Knowing what services are running on the host is important, especially those running as root. A misconfigured or vulnerable service running as root can be an easy win for privilege escalation.
	Flaws have been discovered in many common services such as Nagios, Exim, Samba, ProFTPd, etc. Public exploit PoCs exist for many of them, such as CVE-2016-9566, a local privilege escalation flaw in Nagios Core < 4.2.4.


- `Installed Packages and Versions`: Like running services, it is important to check for any out-of-date or vulnerable packages that may be easily leveraged for privilege escalation.
- `Configuration Files`: Configuration files can hold a wealth of information. It is worth searching through all files that end in extensions such as `.conf` and `.config`, for usernames, passwords, and other secrets.
- `SETUID and SETGID Permissions`: Binaries are set with these permissions to allow a user to run a command as root, without having to grant root-level access to the user. Many binaries contain functionality that can be exploited to get a root shell.
- `Cron Jobs`: Cron jobs on Linux systems are similar to Windows scheduled tasks. They are often set up to perform maintenance and backup tasks.
- `Readable Shadow File` `/etc/shadow`: If the shadow file is readable, you will be able to gather password hashes for all users who have a password set. While this does not guarantee further access, these hashes can be subjected to an offline brute-force attack to recover the cleartext password.
- `Password Hashes in /etc/passwd`: Occasionally, you will see password hashes directly in the /etc/passwd file. This file is readable by all users, and as with hashes in the `shadow` file, these can be subjected to an offline password cracking attack. This configuration, while not common, can sometimes be seen on embedded devices and routers.
- `Unmounted File Systems and Additional Drives`: If you discover and can mount an additional drive or unmounted file system, you may find sensitive files, passwords, or backups that can be leveraged to escalate privileges.

- `Writeable Directories`: It is important to discover which directories are writeable if you need to download tools to the system.
- What tools are installed on the system that we may be able to take advantage of? (Netcat, Perl, Python, Ruby, Nmap, tcpdump, gcc, etc.)
- Anything interesting in the `/etc/hosts` file?
- 
