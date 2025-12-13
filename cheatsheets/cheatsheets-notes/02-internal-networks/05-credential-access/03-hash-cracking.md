# Hash Cracking

Recover plaintext passwords from captured or extracted password hashes using dictionary, rule-based, and brute-force attacks.
Hash cracking is essential after obtaining hashes from SAM, NTDS.dit, shadow files, or network captures.

## Quick Reference

```bash
# Hashcat NTLM hash
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt

# John the Ripper with wordlist
john --wordlist=rockyou.txt --format=NT hashes.txt

# Hashcat with rules
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r best64.rule
```

## Common Hash Formats

```bash
# NTLM (Windows SAM/NTDS.dit)
# Mode: 1000
# Format: 32 hex characters
# Example: 64f12cddaa88057e06a81b54e73b949b

# NTLMv2 (Challenge-Response)
# Mode: 5600
# Format: username::domain:challenge:response
# Example: admin::DOMAIN:1122334455667788:response_hash

# LM Hash
# Mode: 3000
# Format: 32 hex characters (legacy)

# Kerberos TGS-REP (Kerberoasting)
# Mode: 13100
# Format: $krb5tgs$23$*user$realm$spn*$hash

# Kerberos AS-REP (ASREP Roasting)
# Mode: 18200
# Format: $krb5asrep$23$user@domain:hash

# Linux SHA-512 (shadow file)
# Mode: 1800
# Format: $6$salt$hash

# MD5
# Mode: 0
# Format: 32 hex characters

# SHA1
# Mode: 100
# Format: 40 hex characters

# SHA256
# Mode: 1400
# Format: 64 hex characters
```

## Hashcat

```bash
# Basic dictionary attack
hashcat -m 1000 -a 0 hashes.txt wordlist.txt

# Dictionary attack with rules
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r best64.rule

# Multiple rule files
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r best64.rule -r toggles1.rule

# Combination attack (two wordlists)
hashcat -m 1000 -a 1 hashes.txt wordlist1.txt wordlist2.txt

# Mask attack (brute force with pattern)
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?d?d?d?s

# Hybrid attack (wordlist + mask)
hashcat -m 1000 -a 6 hashes.txt wordlist.txt ?d?d?d?s

# Show cracked passwords
hashcat -m 1000 hashes.txt --show

# Resume session
hashcat -m 1000 hashes.txt --session=mysession --restore

# Benchmark mode
hashcat -b

# Specific device (GPU)
hashcat -m 1000 -a 0 -d 1 hashes.txt wordlist.txt

# Optimize for speed
hashcat -m 1000 -a 0 -O hashes.txt wordlist.txt

# Workload profile (1=low, 2=default, 3=high, 4=nightmare)
hashcat -m 1000 -a 0 -w 3 hashes.txt wordlist.txt
```

## Hashcat Mask Attack

```bash
# Mask characters
# ?l = lowercase (abcdefghijklmnopqrstuvwxyz)
# ?u = uppercase (ABCDEFGHIJKLMNOPQRSTUVWXYZ)
# ?d = digit (0123456789)
# ?s = special (!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~)
# ?a = all (?l?u?d?s)
# ?b = binary (0x00 - 0xff)

# 8 character password: Uppercase + 6 lowercase + digit
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?l?d

# Password123! pattern
hashcat -m 1000 -a 3 hashes.txt Password?d?d?d?s

# Custom charset
hashcat -m 1000 -a 3 hashes.txt -1 ?l?u -2 ?d?s ?1?1?1?1?2?2?2?2

# Increment mode (try all lengths up to max)
hashcat -m 1000 -a 3 --increment --increment-min 6 --increment-max 8 hashes.txt ?a?a?a?a?a?a?a?a
```

## John the Ripper

```bash
# Basic dictionary attack
john --wordlist=rockyou.txt hashes.txt

# Specify format
john --wordlist=rockyou.txt --format=NT hashes.txt

# Single crack mode (uses username/GECOS)
john --single hashes.txt

# Incremental mode (brute force)
john --incremental hashes.txt

# With rules
john --wordlist=rockyou.txt --rules hashes.txt

# Show cracked passwords
john --show hashes.txt

# Show formats
john --list=formats

# Show cracked with format
john --show --format=NT hashes.txt

# Resume session
john --restore

# Use all CPU cores
john --wordlist=rockyou.txt --fork=4 hashes.txt
```

## Hash Identification

```bash
# hashID
hashid -j hash.txt

# Example output shows John format
hashid -j 64f12cddaa88057e06a81b54e73b949b
# [+] MD5 [JtR Format: raw-md5]
# [+] NTLM [JtR Format: nt]

# hash-identifier (interactive)
hash-identifier

# Hashcat mode identification
# Check: https://hashcat.net/wiki/doku.php?id=example_hashes
```

## File Cracking with John

```bash
# List available tools
locate *2john*

# ZIP files
zip2john file.zip > zip.hash
john --wordlist=rockyou.txt zip.hash

# RAR files
rar2john file.rar > rar.hash
john --wordlist=rockyou.txt rar.hash

# PDF files
pdf2john file.pdf > pdf.hash
john --wordlist=rockyou.txt pdf.hash

# SSH private keys
ssh2john id_rsa > ssh.hash
john --wordlist=rockyou.txt ssh.hash

# Office documents
office2john document.docx > office.hash
john --wordlist=rockyou.txt office.hash

# KeePass databases
keepass2john database.kdbx > keepass.hash
john --wordlist=rockyou.txt keepass.hash

# BitLocker encrypted drives
bitlocker2john -i Backup.vhd > bitlocker.hash
# Select first hash if multiple
grep "bitlocker\$0" bitlocker.hash > backup.hash
hashcat -m 22100 -a 0 backup.hash rockyou.txt
```

## Custom Wordlist Generation

```bash
# CeWL - Spider website for wordlist
cewl https://company.com -d 4 -m 6 --lowercase -w company.wordlist

# CUPP - User profile wordlist
cupp -i
# Follow prompts for personal info

# Username-anarchy - Generate username variations
username-anarchy -i names.txt > usernames.txt

# Crunch - Generate wordlist with pattern
crunch 8 8 -t Password@@@ -o passwords.txt

# Crunch with charset
crunch 6 8 abcdefghijklmnopqrstuvwxyz0123456789 -o wordlist.txt
```

## Hashcat Rules

```bash
# Common rule files (in /usr/share/hashcat/rules/)
# best64.rule - Best 64 rules
# d3ad0ne.rule - Large rule set
# dive.rule - Comprehensive rules
# toggles1.rule - Case toggling
# InsidePro-PasswordsPro.rule - Professional rules

# Apply rules to wordlist (generate candidates)
hashcat --force wordlist.txt -r custom.rule --stdout | sort -u > mutated.txt

# Custom rule examples
# : = no change
# c = capitalize first letter
# u = uppercase all
# l = lowercase all
# t = toggle case
# $! = append !
# ^! = prepend !
# sa@ = replace a with @
# se3 = replace e with 3
# si1 = replace i with 1
# so0 = replace o with 0

# Example custom.rule file
# c $1$9$9$8$!     # Capitalize + append 1998!
# c $2$0$2$4$!     # Capitalize + append 2024!
# c sa@ $!         # Capitalize + a->@ + append !
# c so0 $!         # Capitalize + o->0 + append !
```

## Filtering Wordlists

```bash
# Filter by minimum length (8 chars)
grep -E '^.{8,}
' rockyou.txt > min8.txt

# Filter by uppercase requirement
grep -E '[A-Z]' min8.txt > uppercase.txt

# Filter by lowercase requirement
grep -E '[a-z]' uppercase.txt > lowercase.txt

# Filter by digit requirement
grep -E '[0-9]' lowercase.txt > digit.txt

# Filter by special character requirement
grep -E '[!@#$%^&*()_+\-=\[\]{};:,.<>?]' digit.txt > special.txt

# Combine filters (8+ chars, upper, lower, digit)
grep -E '^.{8,}' rockyou.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' > filtered.txt

# Remove duplicates
sort -u wordlist.txt > unique.txt

# Count lines
wc -l wordlist.txt
```

## Common Cracking Workflows

```bash
# Workflow 1: NTLM hashes from SAM/NTDS.dit
# Extract hashes with secretsdump
secretsdump.py domain/user:pass@10.10.10.10

# Format: domain\user:RID:LM:NTLM:::
# Extract NTLM portion (4th field)
cat hashes.txt | cut -d: -f4 > ntlm.txt

# Crack with hashcat
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r best64.rule

# Workflow 2: NTLMv2 from Responder
# Responder captures: user::domain:challenge:response
# Crack directly
hashcat -m 5600 -a 0 ntlmv2.txt rockyou.txt

# Workflow 3: Kerberoasting TGS tickets
# Extract with GetUserSPNs.py
GetUserSPNs.py domain/user:pass@10.10.10.10 -request -outputfile tgs.txt

# Crack TGS
hashcat -m 13100 -a 0 tgs.txt rockyou.txt -r best64.rule

# Workflow 4: ASREP Roasting
# Extract with GetNPUsers.py
GetNPUsers.py domain/ -dc-ip 10.10.10.10 -usersfile users.txt -no-pass -outputfile asrep.txt

# Crack ASREP
hashcat -m 18200 -a 0 asrep.txt rockyou.txt

# Workflow 5: Linux shadow file
# Extract hashes
unshadow passwd shadow > linux.hashes

# Crack with John
john --wordlist=rockyou.txt linux.hashes
```

## Hash Format Examples

```bash
# NTLM (from NTDS.dit via secretsdump)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::

# Extract NTLM hash (4th field)
64f12cddaa88057e06a81b54e73b949b

# NTLMv2 (from Responder)
admin::INLANEFREIGHT:1122334455667788:A1B2C3D4E5F6...

# Kerberos TGS (Kerberoasting)
$krb5tgs$23$*sqlservice$DOMAIN.LOCAL$MSSQLSvc/sql01.domain.local:1433*$hash...

# Kerberos ASREP (ASREP Roasting)
$krb5asrep$23$user@DOMAIN.LOCAL:hash...

# Linux SHA-512 (shadow file)
$6$rounds=5000$salt$hash...

# MD5
5f4dcc3b5aa765d61d8327deb882cf99

# SHA1
5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

# SHA256
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

## Performance Optimization

```bash
# Check available devices
hashcat -I

# Use specific GPU
hashcat -m 1000 -a 0 -d 1 hashes.txt wordlist.txt

# Use multiple GPUs
hashcat -m 1000 -a 0 -d 1,2 hashes.txt wordlist.txt

# Optimize for speed (uses more memory)
hashcat -m 1000 -a 0 -O hashes.txt wordlist.txt

# Workload profiles
# -w 1 = Low (desktop usable)
# -w 2 = Default
# -w 3 = High (desktop laggy)
# -w 4 = Nightmare (dedicated cracking)
hashcat -m 1000 -a 0 -w 3 hashes.txt wordlist.txt

# Benchmark specific hash type
hashcat -b -m 1000

# Status during cracking
# Press 's' for status
# Press 'p' for pause
# Press 'r' for resume
# Press 'q' for quit
```

## Notes

**Hash Type Identification:**

Always identify hash type before cracking:
1. Check hash length and format
2. Consider source (Windows, Linux, network capture)
3. Use hashid or hash-identifier
4. Verify with example hashes

**Common Hash Sources:**

- **NTLM**: SAM database, NTDS.dit (Domain Controller)
- **NTLMv2**: Network authentication (Responder, Inveigh)
- **Kerberos TGS**: Service accounts (Kerberoasting)
- **Kerberos ASREP**: Accounts without pre-auth (ASREP Roasting)
- **Linux**: /etc/shadow file
- **Web Apps**: Database dumps, configuration files

**Cracking Strategy:**

1. **Quick wins** (5-10 minutes):
   - Small wordlist (top 10k passwords)
   - No rules
   - Check for weak passwords

2. **Medium effort** (1-2 hours):
   - Rockyou.txt with best64 rules
   - Common patterns
   - Most passwords crack here

3. **Extended** (overnight):
   - Large wordlists
   - Multiple rule sets
   - Combination attacks

4. **Brute force** (days/weeks):
   - Mask attacks
   - Incremental mode
   - Last resort

**Wordlist Selection:**

Start small, scale up:
1. Top 100 passwords
2. Top 10,000 passwords
3. Rockyou.txt (14M)
4. Custom wordlists (CeWL, CUPP)
5. Combined wordlists

**Rule-Based Attacks:**

Rules multiply effectiveness:
- Rockyou.txt = 14M passwords
- Rockyou.txt + best64 = 896M candidates
- Rockyou.txt + best64 + d3ad0ne = billions

Common patterns rules handle:
- Capitalization: `password` → `Password`
- Numbers: `password` → `password123`
- Years: `password` → `password2024`
- Symbols: `password` → `password!`
- Leetspeak: `password` → `p@ssw0rd`

**Mask Attack Patterns:**

Common corporate password patterns:
```bash
# Uppercase + lowercase + digits + special
?u?l?l?l?l?l?d?d?s

# Word + year + symbol
Password?d?d?d?d?s

# Month + year
?u?l?l?l?l?l?l?l?d?d?d?d

# Season + year + symbol
Summer?d?d?d?d?s
```

**Hardware Considerations:**

- **CPU**: Slow, use for simple hashes (MD5, SHA1)
- **GPU**: Fast, 100x-1000x faster than CPU
- **Multiple GPUs**: Linear scaling (2 GPUs = 2x speed)
- **Cloud**: AWS/Azure GPU instances for large jobs

**Hash Cracking Speed:**

Approximate speeds (single RTX 3080):
- MD5: 50 GH/s (billion hashes/sec)
- NTLM: 50 GH/s
- SHA1: 20 GH/s
- SHA256: 10 GH/s
- bcrypt: 50 KH/s (thousand hashes/sec)
- Kerberos TGS: 500 MH/s (million hashes/sec)

**Time Estimates:**

8-character password, all lowercase:
- Keyspace: 26^8 = 208 billion
- At 50 GH/s: ~4 seconds

8-character password, mixed case + digits + symbols:
- Keyspace: 95^8 = 6.6 quadrillion
- At 50 GH/s: ~37 hours

**Success Rates:**

Typical success rates with rockyou.txt + rules:
- NTLM hashes: 60-80%
- NTLMv2: 40-60%
- Kerberos TGS: 30-50%
- Linux SHA-512: 20-40%

**Cracked Password Analysis:**

After cracking, analyze patterns:
```bash
# Show cracked
hashcat -m 1000 hashes.txt --show

# Extract passwords only
hashcat -m 1000 hashes.txt --show | cut -d: -f2 > cracked.txt

# Find common patterns
grep -E '^[A-Z][a-z]+[0-9]+!$' cracked.txt

# Count by length
awk '{print length}' cracked.txt | sort | uniq -c
```

**Common Password Patterns:**

Based on real-world data:
- `Password123!` - Most common corporate
- `Welcome1!` - Common default
- `Summer2024!` - Seasonal pattern
- `CompanyName2024!` - Company-based
- `January2024!` - Month-based

**Ethical Considerations:**

- Only crack hashes with authorization
- Secure cracked passwords properly
- Don't share credentials
- Document findings professionally
- Follow data handling policies

**Troubleshooting:**

Common issues:
- **Wrong hash format**: Verify with hashid
- **Corrupted hash file**: Check for extra spaces/newlines
- **Out of memory**: Use -O flag or reduce workload
- **Slow performance**: Check GPU drivers, use -w 3
- **No results**: Try different wordlists/rules

**Post-Cracking Actions:**

Once passwords cracked:
1. Document credentials securely
2. Test for password reuse
3. Check privilege levels
4. Attempt lateral movement
5. Continue enumeration
6. Report findings

**Tools Comparison:**

- **Hashcat**:
  - GPU-accelerated
  - Fastest option
  - Best for large jobs
  - Requires GPU

- **John the Ripper**:
  - CPU and GPU support
  - Good for file cracking
  - Easier for beginners
  - Slower than Hashcat

**Additional Resources:**

- Hashcat wiki: https://hashcat.net/wiki/
- Example hashes: https://hashcat.net/wiki/doku.php?id=example_hashes
- John formats: https://openwall.info/wiki/john/sample-hashes
- Wordlists: https://github.com/danielmiessler/SecLists
