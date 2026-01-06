[-] Kernel information (continued):
Linux version 5.4.0-45-generic (buildd@lgw01-amd64-033) (gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) #49-Ubuntu SMP Wed Aug 26 13:38:52 UTC 2020
`vulnerable`

## distrubtion
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal

Ubuntu 20.04.1 LTS"

## users
```
-] Users that have previously logged onto the system:
Username         Port     From             Latest
root             tty1                      Wed Jun 11 11:15:54 +0000 2025
mrb3n            tty1                      Tue Sep  8 16:39:37 +0000 2020
tomcat           pts/0    10.10.14.4       Mon Sep  7 18:06:06 +0000 2020
barry            pts/0    10.10.14.3       Sun Sep  6 16:21:41 +0000 2020
vipa0z      pts/0    10.10.14.60      Mon Jul 14 19:32:11 +0000 2025
root             tty1                      Wed Jun 11 11:15:54 +0000 2025

```
## GROUPS AND USERS
```

[-] Group memberships:
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(systemd-timesync) gid=104(systemd-timesync) groups=104(systemd-timesync)
uid=103(messagebus) gid=106(messagebus) groups=106(messagebus)
uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(tss) gid=111(tss) groups=111(tss)
uid=107(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=108(tcpdump) gid=113(tcpdump) groups=113(tcpdump)
uid=109(landscape) gid=115(landscape) groups=115(landscape)
uid=110(pollinate) gid=1(daemon) groups=1(daemon)
uid=111(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=999(systemd-coredump) gid=999(systemd-coredump) groups=999(systemd-coredump)
uid=1000(mrb3n) gid=1000(mrb3n) groups=1000(mrb3n),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
uid=998(lxd) gid=100(users) groups=100(users)
uid=112(mysql) gid=118(mysql) groups=118(mysql)
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
uid=1001(barry) gid=1001(barry) groups=1001(barry),4(adm)
uid=1002(vipa0z) gid=1002(vipa0z) groups=1002(vipa0z)



```

## admins
[-] It looks like we have some admin users:
uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)
uid=1000(mrb3n) gid=1000(mrb3n) groups=1000(mrb3n),4(adm),24(cdrom),27
uid=1001(barry) gid=1001(barry)  groups=1001(barry),4(adm)


## ``cronjobs

```
### JOBS/TASKS ##########################################
[-] Cron jobs:
-rw-r--r-- 1 root root 1042 Feb 13  2020 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Sep  2  2020 .
drwxr-xr-x 97 root root 4096 Jun 11 11:15 ..
-rw-r--r--  1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--  1 root root  712 Mar 27  2020 php
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--  1 root root  191 Apr 23  2020 popularity-contest

/etc/cron.daily:
total 56
drwxr-xr-x  2 root root 4096 Sep  3  2020 .
drwxr-xr-x 97 root root 4096 Jun 11 11:15 ..
-rwxr-xr-x  1 root root  539 Apr 13  2020 apache2
-rwxr-xr-x  1 root root  376 Dec  4  2019 apport
-rwxr-xr-x  1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x  1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x  1 root root 1123 Feb 25  2020 man-db
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x  1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x  1 root root  538 Feb 24  2020 tomcat9
-rwxr-xr-x  1 root root  214 Apr  2  2020 update-notifier-common
```

# to try

- kernel exploit
-  python exploit 
```
   0 lrwxrwxrwx 1 root root    9 Mar 13  2020 /usr/bin/python3 -> python3.8
mysql 
check local web servers
```

```
# SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.8.31


[-] MYSQL version:
mysql  Ver 8.0.21-0ubuntu0.20.04.4 for Linux on x86_64 ((Ubuntu))


[-] Apache version:
Server version: Apache/2.4.41 (Ubuntu)
Server built:   2020-08-12T19:46:17


[-] Apache user configuration:
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data


[-] Installed Apache modules:
Loaded Modules:
 core_module (static)
 so_module (static)
 watchdog_module (static)
 http_module (static)
 log_config_module (static)
 logio_module (static)

```

```
+] Possibly interesting SGID files:
-rwxr-sr-x 1 root mysql 309688 Apr 22 11:51 /snap/core24/988/usr/bin/ssh-agent

```

```
-] Location and contents (if accessible) of .bash_history file(s):
/home/mrb3n/.bash_history
/home/vipa0z/.bash_history
id
ls
ls /var/www/html
cat /var/www/html/flag1.txt 
exit
/home/barry/.bash_history
cd /home/barry
ls
id
ssh-keygen
mysql -u root -p
tmux new -s barry
cd ~
sshpass -p 'i_l0ve_s3cur1ty!' ssh barry_adm@dmz1.blackwood.local
history -d 6
history
history -d 12
history
cd /home/bash
cd /home/barry/
nano .bash_history 
history
exit
history
exit
ls -la
ls -l
history 
history -d 21
history 
exit
id
ls /var/log
history
history -d 28
history

```

```
[-] Location and Permissions (if accessible) of .bak file(s):
-rw-r--r-- 1 root root 862 May  4 16:31 /snap/core24/988/etc/.resolv.conf.systemd-resolved.bak
-rwxr-xr-x 1 root barry 2232 Sep  5  2020 /etc/tomcat9/tomcat-users.xml.bak

```

# barry
```
sshpass -p 'i_l0ve_s3cur1ty!' ssh barry_adm@dmz1.blackwood.local
```

## tomcat
```
"tomcatadm" password="T0mc@t_s3cret_p@ss!" 
```

# mysql wordpress creds
```

| ID | user_login | user_pass                          | user_nicename | user_email                | user_url                | user_registered     | user_activation_key | user_status | display_name |

|  1 | admin      | $P$B69Cem80AlqDfOkt6tesbMo4sfW3ZR1 | admin         | admin@blackwood.local | http://10.129.2.24/blog | 2020-09-02 05:24:52 |                     |           0 | admin        |
+----+------------+------------------------------------+---------------+---------------------------+-------------------------+---------------------+---------------------+-
```

### sessopn token
```
|       19 |       1 | session_tokens                        | a:1:{s:64:"61f33e4e1eb7413d457ec46199a890ed517c340b6baa28749aa8c0207b317826";a:4:{s:10:"expiration";i:1599581706;s:2:"ip";s:10:"10.10.14.3";s:2:"ua";s:66:"Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0";s:5:"login";i:1599408906;}} |

```