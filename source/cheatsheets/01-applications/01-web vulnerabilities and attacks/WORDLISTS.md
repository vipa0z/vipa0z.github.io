subdomain/vhost  fuzzing
```
/opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ
```


directory fuzzing
```shell-session
/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ
```



usernames
```
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
```




tomcat credential stuff
```
/tools/tomcatmgr-default-user-pass.txt
```



common web paths
```
/usr/share/seclists/Discovery/Web-Content/common.txt
```


## default credentials /cracking lists

| Wordlist                                    | Description                                                                                      | Typical Use                                        | Source                                                                                                                           |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `rockyou.txt`                               | A popular password wordlist containing millions of passwords leaked from the RockYou breach.     | Commonly used for password brute force attacks.    | [RockYou breach dataset](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)                      |
| `top-usernames-shortlist.txt`               | A concise list of the most common usernames.                                                     | Suitable for quick brute force username attempts.  | [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt)                         |
| `xato-net-10-million-usernames.txt`         | A more extensive list of 10 million usernames.                                                   | Used for thorough username brute forcing.          | [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Usernames/xato-net-10-million-usernames.txt)                   |
| `2023-200_most_used_passwords.txt`          | A list of the 200 most commonly used passwords as of 2023.                                       | Effective for targeting commonly reused passwords. | [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt) |
| `Default-Credentials/default-passwords.txt` | A list of default usernames and passwords commonly used in routers, software, and other devices. | Ideal for trying default credentials.              | [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.txt)           |
## other useful resources

webshells:
php: phpbash
php https://github.com/Arrexel/phpbash

multi https://github.com/danielmiessler/SecLists/tree/master/Web-Shells

for IIS: antak, 
ASP https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP

`/opt/useful/seclists/Web-Shells`

powershell rev shells:
conpty,ps1

`/tools/conpty.ps1`
nishang
```
/opt/resources/windows/nishang
```