A web API is vulnerable to `Broken Function Level Authorization` (`BFLA`) if it allows unauthorized or unprivileged users to interact with and invoke privileged endpoints, granting access to sensitive operations or confidential information. The difference between `BOLA` and `BFLA` is that, in the case of `BOLA`, the user is authorized to interact with the vulnerable endpoint, whereas in the case of `BFLA`, the user is not.
CWE 200

A SPECIFIC ROLE is required to perform an action on an endpoint, but users without that role can still invoke the endpoint -> vulnerable
![[Pasted image 20251203183215.png]]
you can see the endpoint requires getAll , if we check our role it says no roles assigned
`/api/v1/roles/current-user`
![[Pasted image 20251203183306.png]]
but we are able to call the endpoint
![[Pasted image 20251203183417.png]]

## prevention
enforce an authorization check at the source-code level to ensure that only users with the role could perform the stated action.
