#### nmap
nmap can be used as an initial discovery tool for finding open/hidden ports
```
# quick:
$ nmap -sC -sV [target address] -oA allportscan
full:
$ nmap -p- [target address] -oA allportscan
```

#### amass
bruteforcing for API endpoints using amass, run amass in active mode:
```
amass enum -active  -d target.com --brute API-PATHS.txt

# grep for api:
amass enum -active -d target.com |grep api
```

#### Gobuster
 For directory discovery. not API specific but can help when searching for API paths or admin panels:
```
gobuster dir -u https://target:port -w dir-list2.3-medium
   /community

# deeper into a specific path:
gobuster dir -u https://target:port/community -w dir-list2.3-medium
```

#### kiterunner:
fuzzing tool, Main API discovery scanner, with built-in wordlists.
```
kr -h
```

#### Postman:
 postman can be used as a  proxy to capture traffic, manually save interesting endpoints.
side note: you can copy requests as curl using dev tools and import them to postman. it will duplicate the request for you


#### mitmproxy:
useful proxy tool. combine with mitm2swagger to generate docs.

#### mitm2swagger:
```
sudo mitmproxy2swagger -i ~/Downloads/flows -o spec.yml -p http://crapí.apisec.ai -f flow --examples
```
generates spec.yml, browse to editor.swagger.io and import the spec file.
also import to postman.
![[ss/Pasted image 20251109235350.png]]