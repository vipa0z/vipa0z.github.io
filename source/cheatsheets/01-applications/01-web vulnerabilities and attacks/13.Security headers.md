| Concept                               | Protects           | Blocks                         |
| ------------------------------------- | ------------------ | ------------------------------ |
| **SOP**                               | User privacy       | Reading cross-origin responses |
| **CORS**                              | Relax SOP safely   | Allows specific origins        |
| **CSP**                               | XSS                | Inline/external unsafe scripts |
| **X-Frame-Options / frame-ancestors** | UI control         | Clickjacking                   |
| **HSTS**                              | Transport security | Downgrade MITM                 |
| **X-Content-Type-Options**            | MIME sniffing      | Content spoofing               |
| **Referrer-Policy**                   | Info leaks         | URL/token leaking              |
| **COOP/COEP/CORP**                    | Advanced isolation | XS-Leaks, side-channel attacks |
## 1. Same-Origin Policy (SOP) - The Foundation

**What it is:** The browser's fundamental security model that restricts how documents or scripts from one origin can interact with resources from another origin.

**Origin Definition:** Protocol + Domain + Port must all match

- `https://example.com:443` ≠ `http://example.com:80` (different protocol & port)
- `https://api.example.com` ≠ `https://example.com` (different subdomain)

**What SOP Restricts:**

- **JavaScript access to cross-origin data:** You cannot read responses from other origins using fetch/XMLHttpRequest
- **DOM access:** Scripts from one origin cannot read/manipulate the DOM of pages from another origin
- **Cookies and storage:** Cannot access cookies, localStorage, or sessionStorage from other origins

**What SOP Allows:**

- Embedding resources: `<img>`, `<script>`, `<link>`, `<video>`, `<iframe>` tags can load cross-origin resources
- - Form submissions to other origins
- Redirects
 Without SOP, a malicious site could read your Gmail, bank account, or any site where you're logged in.
---
### CORS
controls SOP by relaxing its restrictions
### Key CORS Headers

**Response Headers (Server → Browser):**

- `Access-Control-Allow-Origin`: Specifies allowed origins (`*`, specific origin, or null)
- `Access-Control-Allow-Methods`: Permitted HTTP methods
- `Access-Control-Allow-Headers`: Allowed custom headers
- `Access-Control-Allow-Credentials`: Whether cookies/auth can be sent (true/false)
- `Access-Control-Expose-Headers`: Which response headers JS can access
- `Access-Control-Max-Age`: How long to cache preflight results (seconds)
---
## 3. Content Security Policy (CSP) - Defense Against XSS

**What it is:** A security header that controls which resources the browser is allowed to load, preventing injection attacks.
### CSP Directives

**Core Directives:**
- `default-src`: Fallback for all other directives
- `script-src`: Where scripts can load from
- `style-src`: Where stylesheets can load from
- `img-src`: Where images can load from
- `connect-src`: Where fetch/XHR/WebSocket
---
### secure headers obtained from OWASP
https://owasp.org/www-project-secure-headers/ci/headers_add.json