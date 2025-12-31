`Port 111 2049`
configuration folder: `/etc/exports`


nmap scripts:
```
--script nfs* -p111,2049
--script rpcinfo #included in sC flag
```

| **Command**                                               | **Description**                              |
| --------------------------------------------------------- | -------------------------------------------- |
| mkdir 'name' &&`showmount -e <FQDN/IP>`                   | Show available NFS shares.                   |
| `mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock` | Mount the specific NFS share to ./target-NFS |
| `umount ./target-NFS`                                     | Unmount the specific NFS share.              |
| `ls -l mnt/nfs/`                                          | List Contents with Usernames & Group Names   |
| <br>`ls -n mnt/nfs/`                                      | guid & uid                                   |
