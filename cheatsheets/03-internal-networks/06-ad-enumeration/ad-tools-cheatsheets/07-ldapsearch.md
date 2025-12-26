


### 1) Quickly discover the correct search base (namingContext / defaultNamingContext)

Run this to get the domain naming contexts from the server (use your same bind DN/password):
```
ldapsearch -x -H ldap://172.16.5.5 \
  -D "svc_reporting@inlanefreight.local" -w 'Reporter1!' \
  -s base -b "" -LLL namingContexts defaultNamingContext

```
### 2. get group membership for a user
```
ldapsearch -x -H ldap://172.16.5.5 \
  -D "svc_reporting@inlanefreight.local" -w 'Reporter1!' \
  -b "DC=INLANEFREIGHT,DC=LOCAL" "(sAMAccountName=svc_reporting)" memberOf -LLL \
  | grep '^memberOf:' \
  | sed -E 's/memberOf: CN=([^,]+).*/\1/'

```