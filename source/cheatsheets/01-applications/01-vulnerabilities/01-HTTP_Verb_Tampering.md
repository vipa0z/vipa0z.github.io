# HTTP Verb Tampering Cheatsheet

## Introduction
HTTP Verb Tampering vulnerabilities occur when a web server or application has insecure configurations or coding that allows an attacker to bypass authentication or authorization by using unexpected HTTP methods (verbs).

---

## Discovery

### Testing for Insecure Configurations
Web servers might limit access based on specific methods (e.g., `<Limit GET POST>`). Attackers can try other methods to bypass these restrictions.

**Common Methods to Test:**
-   `HEAD`
-   `PUT`
-   `DELETE`
-   `OPTIONS`
-   `PATCH`

**Manual Testing:**
```bash
curl -i -X HEAD http://TARGET/admin
curl -i -X PUT http://TARGET/admin
curl -i -X OPTIONS http://TARGET/admin
```

### Testing for Insecure Coding
Some backend languages/frameworks might only check for specific request types (e.g., `$_GET` or `$_POST`) but process input from a general collection (e.g., `$_REQUEST`).

**Example (PHP):**
If the code checks `if (isset($_GET['code']))` but uses `$_REQUEST['code']` in the query, you might be able to bypass WAFs or logic checks by sending the parameter in the body (POST) or cookie.

**Vulnerable Functions:**
| Language | Function | Description |
| :--- | :--- | :--- |
| **PHP** | `$_REQUEST['param']` | Contains data from GET, POST, and COOKIE. |
| **Java** | `request.getParameter('param')` | Retrieves from query string or post body. |
| **C#** | `Request['param']` | Retrieves from query string, form, cookies, or server variables. |

---

## Exploitation

### Bypassing Authentication
If the server config looks like this:
```apache
<Limit GET POST>
    Require valid-user
</Limit>
```
Try sending a `HEAD` request to access the resource without authentication.

### Bypassing WAFs/Filters
If a WAF blocks `GET` requests containing malicious payloads (e.g., SQLi), try sending the same payload via `POST` or other methods if the application uses a promiscuous parameter retrieval method (like `$_REQUEST`).

---

## Prevention

1.  **Strict Configuration**: Apply access controls to **all** HTTP methods, not just specific ones.
    ```apache
    <LimitExcept GET POST>
        Deny from all
    </LimitExcept>
    ```
2.  **Validate Request Method**: In application code, strictly check the request method (e.g., `$_SERVER['REQUEST_METHOD'] === 'POST'`).
3.  **Use Specific Variables**: Use `$_GET` or `$_POST` instead of `$_REQUEST` to avoid ambiguity.
