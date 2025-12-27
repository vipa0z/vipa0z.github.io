# SSH `PORT 22`
List Authentication Methods
```shell-session
$ ssh -v cry0l1t3@10.129.14.132
```
#### Change Authentication Method
```shell-session
$ ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
```
for a banner with `SSH-2.0-OpenSSH_8.2p1`, we are dealing with an OpenSSH version 8.2p1 which only accepts the SSH-2 protocol version
