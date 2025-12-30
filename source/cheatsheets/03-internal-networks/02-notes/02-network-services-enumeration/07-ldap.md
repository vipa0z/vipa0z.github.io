# LDAP

`LDAP` (Lightweight Directory Access Protocol) is `a protocol` used to `access and manage directory information`. A `directory` is a `hierarchical data store` that contains information about network resources such as `users`, `groups`, `computers`, `printers`, and other devices. LDAP provides some excellent functionality:

- LDAP is `commonly used` for providing a `central location` for `accessing` and `managing` directory services.

- Directory services are collections of information about the organisation, its users, and assets–like usernames and passwords.

- LDAP enables organisations to store, manage, and secure this information in a standardised way. Here are some common use cases:

| Functionality | Description                                                                                                                                                                                                                       |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Encryption`  | LDAP `does not encrypt its traffic by default`, which exposes sensitive data to potential eavesdropping and tampering. LDAPS (LDAP over SSL) or StartTLS must be used to enable encryption.                                       |
| `Injection`   | `Vulnerable to LDAP injection attacks`, where malicious users can manipulate LDAP queries and `gain unauthorised access` to data or resources. To prevent such attacks, input validation and output encoding must be implemented. |

# Interacting with ldap

`ldapsearch` is a command-line utility used to search for information stored in a directory using the LDAP protocol. It is commonly used to query and retrieve data from an LDAP directory service.

```shell-session
$ ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"

```

This command can be broken down as follows:

- Connect to the server `ldap.example.com` on port `389`.
- Bind (authenticate) as `cn=admin,dc=example,dc=com` with password `secret123`.
- Search under the base DN `ou=people,dc=example,dc=com`.
- Use the filter `(mail=john.doe@example.com)` to find entries that have this email address.
  The server would process the request and send back a response, which might look something like this:

```ldap
dn: uid=jdoe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: John Doe
sn: Doe
uid: jdoe
mail: john.doe@example.com

result: 0 Success
```

## LDAP Injection

`LDAP injection` is an attack that `exploits web applications that use LDAP` (Lightweight Directory Access Protocol) for authentication or storing user information. The attacker can `inject malicious code` or `characters` into LDAP queries to alter the application's behaviour, `bypass security measures`, and `access sensitive data` stored in the LDAP directory.

| Input    | Description                                                                                                                                                                                                                                |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `*`      | An asterisk `*` can `match any number of characters`.                                                                                                                                                                                      |
| `( )`    | Parentheses `( )` can `group expressions`.                                                                                                                                                                                                 |
| `\|`     | A vertical bar `\|` can perform `logical OR`.                                                                                                                                                                                              |
| `&`      | An ampersand `&` can perform `logical AND`.                                                                                                                                                                                                |
| `(cn=*)` | Input values that try to bypass authentication or authorisation checks by injecting conditions that `always evaluate to true` can be used. For example, `(cn=*)` or `(objectClass=*)` can be used as input values for a username or passwo |

For example, suppose an application uses the following LDAP query to authenticate users:

```php
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```

If an attacker injects the `*` character into the `$username` field, the LDAP query will match any user account with any password. This would allow the attacker to gain access to the application with any password, as shown below:

```php
$username = "*";
$password = "dummy";
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```

# Enumeration

### nmap scan

```shell-session
$ nmap -p- -sC -sV --open --min-rate=1000 10.129.204.229

80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))


389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X

```

# Mitigation

To mitigate the risks associated with LDAP injection attacks, it is crucial to `thoroughly validate` and `sanitize user input` before incorporating it into LDAP queries. This process should involve `removing LDAP-specific special characters` like `*` and `employing parameterised queries` to ensure user input is `treated solely as data`, not executable code.

`LDAP://HostName[:PortNumber][/DistinguishedName]`

- Note that a domain may have multiple DCs, so setting the domain name could
  potentially resolve to the IP address of any DC in the domain.

- to make our enumeration as accurate as possible, we should look for the DC
  that holds the most updated information. This is known as the Primary Domain Controller
  (PDC).1021 There can be only one PDC in a domain. To find the PDC, we need to find the DC
  holding the PdcRoleOwner property. We’ll eventually use PowerShell and a specific .NET class to
  find this.
  a DistinguishedName (DN)1022 is a part of the LDAP path. A DN is a name that uniquely
  identifies an object in AD, including the domain itself. If we aren’t familiar with LDAP, this may be
  somewhat confusing so let’s go into a bit more detail.

---

stephanie domain user. We know that stephanie is a user object within the corp.com domain. With
this, the DN may (although we cannot be sure yet) look something like this:
`CN=Stephanie,CN=Users,DC=corp,DC=com`

- The CN is known as the Common Name, which specifies the identifier of an object in the domain. While we normally refer to “DC” as the Domain Controller in AD terms, “DC” means Domain Component when we are referring to a Distinguished Name. The Domain Component represents the top of an LDAP tree and in this case we refer to it as the Distinguished Name ofthe domain itself.

---

When reading a DN, we start with the Domain Component objects on the right side and move to the left. In the example above, we have four components, starting with two components named` DC=corp,DC=com`. The Domain Component objects as mentioned above represent the top of an LDAP tree following the required naming standard.

`CN=Users` represents the Common Name for the container where the user object is stored (also known as the parent container).
CN=`Stephanie` represents the Common Name for the user object itself, which is also lowest in the hierarchy.

### FINDING PRIMARY DOMAIN CONTROLLER

a domain may have multiple DCs, so setting the domain name could
potentially resolve to the IP address of any DC in the domain.
to make our enumeration as accurate as possible, we should look for the DC that holds the most updated information. This is known as the Primary Domain Controller
(PDC). There can be only one PDC in a domain. To find the PDC, we need to find the DC
holding the PdcRoleOwner property.
Get `DC` with `PDCRole`
![](security/Screenshots/Pasted%20image%2020241217153539.png)

![](security/Screenshots/Pasted%20image%2020241217153632.png)

```
public System.DirectoryServices.ActiveDirectory.DomainController PdcRoleOwner { get; }
```

![](Pasted%20image%2020241217153517.png
![](security/Screenshots/Pasted%20image%2020241217152953.png)
`System.DirectoryServices.ActiveDirectory namespace`

##### Get domain controller object in variable for future use

```
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$domainObj
```

##### store name of Primary DC in variable

```

$PDC = $domainObj.PdcRoleOwner.Name
#DC1.corp.com
```

`` here we're accessing the nested`PdcRoleOwner`DC Object and retrieving it's`name`property, sort of like what were doing with`$domainObj`

```
DC:
	 {
	 Name: DC3.corp.com
	 PdcRoleOwner:{
			 Name:DC1.corp.com
		    }
    }
```

In my current setup:
![](security/Screenshots/Pasted%20image%2020241217161806.png)
`GOT.local` is the domain name
`WINTER-DC.GOT.local` is the Primary domain Controller

### Getting the right DN for the DC were querying

We can use ADSI directly in PowerShell to retrieve the DN. We’ll use two single quotes to indicate that the search starts at the top of the AD hierarchy.

```
#example:
PS Mag> ([adsi]'').distinguishedName
DC=GOT,DC=local
```

PAGE 699 OSCP
