# IMAP (Port 143, 993)

Enumerate and interact with IMAP (Internet Message Access Protocol) mail servers to access mailboxes and retrieve emails.
IMAP keeps emails on the server and syncs across devices, with port 143 for unencrypted and 993 for SSL/TLS connections.

## Banner Grabbing

### Netcat
```bash
nc -nv 10.10.10.10 143
```

### Telnet
```bash
telnet 10.10.10.10 143
```

### OpenSSL (IMAPS - Port 993)
```bash
openssl s_client -connect 10.10.10.10:993
```

## IMAP Commands

**Note:** All IMAP commands must be prefixed with a tag (e.g., `a`, `1`, `A001`)

### Authentication
```bash
# Login
a LOGIN username password

# Logout
a LOGOUT
```

### Mailbox Operations
```bash
# List all mailboxes
a LIST "" *

# List subscribed mailboxes
a LSUB "" *

# Create mailbox
a CREATE "INBOX"

# Delete mailbox
a DELETE "INBOX"

# Rename mailbox
a RENAME "ToRead" "Important"

# Select mailbox
a SELECT INBOX

# Unselect mailbox
a UNSELECT INBOX

# Check mailbox status
a STATUS INBOX (MESSAGES UNSEEN)
```

### Message Operations
```bash
# Fetch all message UIDs and flags
a FETCH 1:* (UID FLAGS)

# Fetch message headers
a FETCH 1 (BODY[HEADER])

# Fetch entire message
a FETCH 1 (BODY[])

# Fetch multiple messages
a FETCH 1:5 (BODY[])

# Fetch all messages
a FETCH 1:* (BODY[])

# Search for messages
a SEARCH ALL
a SEARCH FROM "user@domain.com"
a SEARCH SUBJECT "password"

# Mark message as deleted
a STORE 1 +FLAGS (\Deleted)

# Expunge deleted messages
a EXPUNGE

# Close mailbox (expunge and unselect)
a CLOSE
```

## Enumeration

### Nmap Scripts
```bash
# IMAP enumeration
nmap -p143,993 --script imap-capabilities,imap-ntlm-info 10.10.10.10

# IMAP brute force
nmap -p143 --script imap-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

### Manual Enumeration
```bash
# Connect and enumerate
nc -nv 10.10.10.10 143
a CAPABILITY
a LOGIN user password
a LIST "" *
a SELECT INBOX
a FETCH 1:* (UID FLAGS)
a FETCH 1 (BODY[])
a LOGOUT
```

## cURL Access

### List and Retrieve Emails
```bash
# List mailboxes
curl -k 'imaps://10.10.10.10' --user user:password

# List emails in INBOX
curl -k 'imaps://10.10.10.10/INBOX' --user user:password

# Retrieve specific email
curl -k 'imaps://10.10.10.10/INBOX;UID=1' --user user:password

# Search for emails
curl -k 'imaps://10.10.10.10/INBOX' --user user:password -X 'SEARCH FROM "admin"'
```

## Brute Force

### Hydra
```bash
# IMAP brute force
hydra -l user -P /usr/share/wordlists/rockyou.txt imap://10.10.10.10

# IMAPS brute force
hydra -l user -P /usr/share/wordlists/rockyou.txt imaps://10.10.10.10
```

## Common Workflow

### Full Email Enumeration
```bash
# Connect
openssl s_client -connect 10.10.10.10:993

# Login
a LOGIN user@domain.com password

# List mailboxes
a LIST "" *

# Select INBOX
a SELECT INBOX

# Get message count and flags
a FETCH 1:* (UID FLAGS)

# Read all messages
a FETCH 1:* (BODY[])

# Search for sensitive keywords
a SEARCH BODY "password"
a SEARCH BODY "credential"
a SEARCH SUBJECT "confidential"

# Logout
a LOGOUT
```

## Notes

**IMAP vs POP3:**
- IMAP keeps emails on server, POP3 downloads and typically deletes
- IMAP supports multiple folders, POP3 only has inbox
- IMAP syncs across devices, POP3 is single-device focused
- IMAP is more complex but more flexible

**Security Considerations:**
- IMAP transmits credentials in cleartext on port 143
- Always use IMAPS (port 993) for encrypted communication
- Check for default credentials and weak passwords
- IMAP can expose sensitive information in email bodies

**Common Misconfigurations:**
- Anonymous access enabled
- Weak authentication mechanisms
- Verbose logging exposing credentials
- Unencrypted connections allowed

**Useful Searches:**
- `SEARCH FROM "admin"` - Find emails from admin
- `SEARCH SUBJECT "password"` - Find password-related emails
- `SEARCH BODY "credential"` - Find credentials in email bodies
- `SEARCH SINCE "1-Jan-2024"` - Find recent emails
- `SEARCH UNSEEN` - Find unread emails

**Command Prefixes:**
- Commands must be prefixed with a tag (a, 1, A001, etc.)
- Server responses include the same tag
- Allows multiple commands to be sent asynchronously
