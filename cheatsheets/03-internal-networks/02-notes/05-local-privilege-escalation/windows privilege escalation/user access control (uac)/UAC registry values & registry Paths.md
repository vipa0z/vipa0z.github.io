query registry values
```
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
```
## Registry Settings


| Setting                         | Type  | Values                                                                                                                                                                                                                                                                                                                                | Description                                                                         |
| ------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **EnableLUA**                   | DWORD | `0` = UAC disabled<br>`1` = UAC enabled (default)                                                                                                                                                                                                                                                                                     | Master switch for UAC functionality. Requires reboot.                               |
| **ConsentPromptBehaviorAdmin**  | DWORD | `0` = Elevate without prompting         <br>`1` = Prompt for credentials on secure desktop          <br>`2` = Prompt for consent on secure desktop (default)              <br>`3` = Prompt for credentials                 <br>`4` = Prompt for consent                         <br>`5` = Prompt for consent for non-Windows binaries | Controls prompt behavior for administrator accounts. Only works when EnableLUA = 1. |
| **PromptOnSecureDesktop**       | DWORD | `0` = Use normal desktop<br>`1` = Use secure desktop (default)                                                                                                                                                                                                                                                                        | Controls whether UAC prompts appear on secure desktop or normal desktop.            |
| **ConsentPromptBehaviorUser**   | DWORD | `0` = Auto deny elevation requests<br>`1` = Prompt for credentials on secure desktop (default)<br>`3` = Prompt for credentials                                                                                                                                                                                                        | Controls prompt behavior for standard users.                                        |
| **EnableInstallerDetection**    | DWORD | `0` = Disabled<br>`1` = Enabled (default)                                                                                                                                                                                                                                                                                             | Detects application installations and prompts for elevation.                        |
| **ValidateAdminCodeSignatures** | DWORD | `0` = Disabled (default)<br>`1` = Enabled                                                                                                                                                                                                                                                                                             | Requires digitally signed executables for elevation.                                |
| **EnableSecureUIAPaths**        | DWORD | `0` = Disabled<br>`1` = Enabled (default)                                                                                                                                                                                                                                                                                             | Enforces secure paths for UI Accessibility applications.                            |
| **EnableVirtualization**        | DWORD | `0` = Disabled<br>`1` = Enabled (default)                                                                                                                                                                                                                                                                                             | Enables file and registry virtualization for legacy apps.                           |
| **FilterAdministratorToken**    | DWORD | `0` = Disabled (default)<br>`1` = Enabled                                                                                                                                                                                                                                                                                             | Applies UAC restrictions to built-in Administrator account.                         |


### Registry Paths

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`

### Registry Values Table

## Key Differences Summary