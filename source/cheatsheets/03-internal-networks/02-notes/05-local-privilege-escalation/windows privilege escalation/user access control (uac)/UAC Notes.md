User Account Control (UAC) is a Windows security feature that works differently depending on the type of account being used
### token filtering

#### **1. for default admin (rid 500)**
- The built-in Administrator account runs with full administrative privileges by default
- No split token mechanism is used
- UAC prompts are suppressed for this account

#### 2. **for users added to local administrators group:**
- When a regular user account is added to the local Administrators group, UAC implements a "split token" approach:
- During logon, Windows creates two access tokens for the user
- A **full admin token** containing all administrative privileges
- A **filtered standard user token** with administrative privileges removed

|Aspect|Admin Group Users|Built-in Administrator|
|---|---|---|
|Token Filtering|Yes (split tokens)|No|
|UAC Prompts|Yes|No|
|Default Privileges|Standard user|Full admin|
|Elevation Required|Yes|No|
|Security Level|Higher|Lower|
UAC behavior can be modified through:

- Group Policy settings
- Registry keys under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
- Key settings like `EnableLUA`, `ConsentPromptBehaviorAdmin`, etc.
---
# UAC (User Account Control) 

## Account Types and Behavior

### Users in Administrators Group

- Uses **split token** approach during logon
- Creates both full admin token and filtered standard user token
- Runs with standard user privileges by default
- Requires elevation prompts for administrative tasks
- Subject to Admin Approval Mode

### Built-in Administrator Account (RID 500)

- No token filtering applied
- Runs with full administrative privileges by default
- UAC prompts are suppressed
- No elevation barrier (higher security risk)
- Microsoft recommends against daily use

|Aspect|Admin Group Users|Built-in Administrator|Normal Prompts|Secure Desktop Prompts|
|---|---|---|---|---|
|Token Filtering|Yes (split tokens)|No|N/A|N/A|
|UAC Prompts|Yes|No|Lower security|Higher security|
|Default Privileges|Standard user|Full admin|Interactive desktop|Isolated desktop|
|Elevation Required|Yes|No|Vulnerable to attacks|Protected from attacks|
|Security Level|Higher|Lower|Minimal protection|Strong protection|

## Prompt Types

### Normal Consent Prompts

- Appears as regular window on current desktop
- Desktop remains at normal brightness
- Other applications remain interactive
- Lower security protection
- Vulnerable to UI manipulation attacks

### Secure Desktop Consent Prompts

- Desktop dims/darkens (grayed out)
- Runs in isolated Winlogon desktop session
- All other applications become non-interactive
- Higher security protection
- Protected from malware interference

## Registry Settings

| Setting                        | Values                                                                                                                                                                                                                                                     | Description                                                                         |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **EnableLUA**                  | `0` = UAC disabled<br>`1` = UAC enabled (default)                                                                                                                                                                                                          | Master switch for UAC functionality. Requires reboot.                               |
| **ConsentPromptBehaviorAdmin** | `0` = Elevate without prompting<br>`1` = Prompt for credentials on secure desktop<br>`2` = Prompt for consent on secure desktop (default)<br>`3` = Prompt for credentials<br>`4` = Prompt for consent<br>`5` = Prompt for consent for non-Windows binaries | Controls prompt behavior for administrator accounts. Only works when EnableLUA = 1. |
| **PromptOnSecureDesktop**      | `0` = Use normal desktop<br>`1` = Use secure desktop (default)                                                                                                                                                                                             | Controls whether UAC prompts appear on secure desktop or normal desktop.            |


## Operations Requiring UAC Elevation

### System and Configuration Changes

- **Installing/Uninstalling Software**
    - MSI packages and executables marked for elevation
    - Device drivers installation
    - System-wide software installations
- **System Settings and Configuration**
    - Changing UAC settings
    - Modifying Windows Firewall settings
    - Changing system time and date
    - Modifying network adapter settings
    - Adding/removing Windows features

### File System Operations

- **Protected Directory Access**
    - Writing to `C:\Program Files\` and subdirectories
    - Writing to `C:\Program Files (x86)\` and subdirectories
    - Writing to `C:\Windows\` and subdirectories
    - Writing to `C:\Windows\System32\` and subdirectories
    - Modifying system files
- **File Permissions and Ownership**
    - Taking ownership of system files
    - Changing file permissions on protected files
    - Accessing files owned by other users (with restricted access)

### Registry Operations

- **Protected Registry Keys**
    - `HKEY_LOCAL_MACHINE` (HKLM) modifications
    - System-wide registry changes
    - UAC policy registry keys
    - Service-related registry entries

### Service and Process Management

- **Windows Services**
    - Starting/stopping/configuring Windows services
    - Installing new services
    - Modifying service startup types
    - Changing service accounts
- **Process Management**
    - Terminating system processes
    - Debugging system-level processes
    - Accessing processes running as other users

### Hardware and Device Management

- **Device Operations**
    - Installing unsigned drivers
    - Modifying hardware settings
    - Accessing low-level hardware interfaces
    - Changing device driver settings

### Network and Security Operations

- **Network Configuration**
    - Binding/unbinding network protocols
    - Configuring network adapters
    - Modifying hosts file (`C:\Windows\System32\drivers\etc\hosts`)
    - Port binding for system services
- **Security Settings**
    - Modifying local security policies
    - Changing user account settings for other users
    - Modifying audit policies
    - Certificate store modifications (local machine)

### Administrative Tools and Utilities

- **Built-in Administrative Tools**
    - Registry Editor (regedit.exe) - when accessing HKLM
    - Computer Management console
    - Services.msc console
    - Event Viewer (for clearing system logs)
    - Local Group Policy Editor (gpedit.msc)
    - Certificate Manager (local machine certificates)

### Application-Specific Elevation

- **Applications with Elevation Requirements**
    - Applications with `requireAdministrator` in their manifest
    - Applications attempting to write to protected locations
    - Applications requesting elevated permissions programmatically
    - Legacy applications without UAC awareness

## Security Recommendations

- Keep **EnableLUA = 1** (UAC enabled)
- Use **ConsentPromptBehaviorAdmin = 2** (consent on secure desktop)
- Keep **PromptOnSecureDesktop = 1** (secure desktop enabled)
- Avoid daily use of built-in Administrator account (RID 500)
- Use regular admin accounts in Administrators group instead