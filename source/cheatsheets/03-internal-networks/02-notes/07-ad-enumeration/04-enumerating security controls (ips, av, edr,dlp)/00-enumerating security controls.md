
## defender
will block tools such as `PowerView`.

```powershell-session
PS C:\htb> Get-MpComputerStatus

RealTimeProtectionEnabled       : True
```
## AppLocker
[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft's application whitelisting solution and gives system administrators control over which applications and files users can run. It provides granular control over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers. It is common for organizations to block cmd.exe and PowerShell.exe and write access to certain directories, but this can all be bypassed.
blocks powershell exeutable but can bypassed by looking at the other locations where other versions of ps exist.
```powershell-session
 Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

PathConditions      : {%SYSTEM32%\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE}
Description         : Blocks Domain Users from using PowerShell on workstations
UserOrGroupSid      : S-1-5-21-2974783224-3764228556-2640795941-513
Action              : Deny
```

## PowerShell Constrained Language Mode

PowerShell [Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) locks down many of the features needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, XAML-based workflows, PowerShell classes, and more.

We can quickly enumerate whether we are in Full Language Mode or Constrained Language Mode.
```powershell-session
PS C:\htb> $ExecutionContext.SessionState.LanguageMode
```

## 