## R

`R-services` span across the ports `512`, `513`, and `514`
The [R-commands](https://en.wikipedia.org/wiki/Berkeley_r-commands) suite consists of the following programs:

- rcp (`remote copy`)
- rexec (`remote execution`)
- rlogin (`remote login`)
- rsh (`remote shell`)
- rstat
- ruptime
- rwho (`remote who`)

| Command  | Service Daemon | Port | Transport Protocol | Description                                                                                                                                                                                                                                                                |
| -------- | -------------- | ---- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rcp`    | `rshd`         | 514  | TCP                | Copy a file or directory bidirectionally from the local system to the remote system (or vice versa) or from one remote system to another. It works like the `cp` command on Linux but provides `no warning to the user for overwriting existing files on a system`.        |
| `rsh`    | `rshd`         | 514  | TCP                | Opens a shell on a remote machine without a login procedure. Relies upon the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files for validation.                                                                                                                 |
| `rexec`  | `rexecd`       | 512  | TCP                | Enables a user to run shell commands on a remote machine. Requires authentication through the use of a `username` and `password` through an unencrypted network socket. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files. |
| `rlogin` | `rlogind`      | 513  | TCP                | Enables a user to log in to a remote host over the network. It works similarly to `telnet` but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.                                     |

```shell-session
$ sudo nmap -sV -p 512,513,514 10.0.17.2

Starting Nmap 7.80 ( https://nmap.org ) at 2022-12-02 15:02 EST
Nmap scan report for 10.0.17.2
Host is up (0.11s latency).

PORT    STATE SERVICE    VERSION
512/tcp open  exec?
513/tcp open  login?
514/tcp open  tcpwrapped
```

The `hosts.equiv` and `.rhosts` files contain a list of hosts (`IPs` or `Hostnames`) and users that are `trusted` by the local host when a connection attempt is made using `r-commands`. Entries in either file can appear like the following:

#### Sample .rhosts File

Linux Remote Management Protocols

````shell-session
$ cat .rhosts
```shell-session
vipa0z     10.0.17.5
+               10.0.17.10
+               +
````

the `+` modifier allows any external user to access r-commands from the `vipa0z` user account via the host with the IP address `10.0.17.10`.

Misconfigurations in either of these files can allow an attacker to authenticate as another user without credentials, with the potential for gaining code execution. .

login with rlogin

```shell-session
$ rlogin 10.0.17.2 -l vipa0z
```

Listing Authenticated Users Using Rwho

```shell-session
rwho

root     web01:pts/0 Dec  2 21:34
vipa0z     workstn01:tty1  Dec  2 19:57  2:25
```

list Authenticated users

```shell-session
 rusers -al 10.0.17.5
```

Remote management services can provide us with a treasure trove of data and often be abused for unauthorized access through either weak/default credentials or password re-use. We should always probe these services for as much information as we can gather and leave no stone unturned, especially when we have compiled a list of credentials from elsewhere in the target network.
