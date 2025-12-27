The `Set User ID upon Execution` (`setuid`) permission can allow a user to execute a program or script with the permissions of another user, typically with elevated privileges. The `setuid` bit appears as an `s`.

```shell-session
$ find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

The Set-Group-ID (setgid) permission is another special permission that allows us to run binaries as if we were part of the group that created them. These files can be enumerated using the following command: `find / -uid 0 -perm -6000 -type f 2>/dev/null`. These files can be leveraged in the same manner as `setuid` binaries to escalate privileges.

```shell-session
$ find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null

-rwsr-sr-x 1 root root 85832 Nov 30  2017 /usr/lib/snapd/snap-confine
```

## GTFOBins

The [GTFOBins](https://gtfobins.github.io) project is a curated list of binaries and scripts that can be used by an attacker to bypass security restrictions. Each page details the program's features that can be used to break out of restricted shells, escalate privileges, spawn reverse shell connections, and transfer files. For example, `apt-get` can be used to break out of restricted environments and spawn a shell by adding a Pre-Invoke command:

```shell-session
$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

# sudo -l

if we have sodu -l shows that we can run a file as root
, if the file executes commands best on arguement for example tcpdump can execute files..
we can then create a netcat listener to get root.

gtfobins
