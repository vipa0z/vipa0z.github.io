
---

Web APIs are susceptible to the same security misconfigurations that can compromise traditional web applications. One typical example is a web API endpoint that accepts user-controlled input and incorporates it into SQL queries without proper validation, thereby allowing [Injection](https://owasp.org/Top10/A03_2021-Injection/) attacks.

## Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

The endpoint we will be practicing against is vulnerable to [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html).


### Missing security headers

The `Access-Control-Allow-Origin` is a CORS (cross-origin resource sharing) header. This header indicates whether the response it is related to can be shared with requesting code from the given origin. In other words, if siteA requests a resource from siteB, siteB should indicate in its `Access-Control-Allow-Origin` header that siteA is allowed to fetch that resource, if not, the access is blocked due to Same Origin Policy (SOP).