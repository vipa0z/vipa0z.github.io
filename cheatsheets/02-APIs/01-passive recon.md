### Why Passive Recon

**Passive API Reconnaissance** is the act of obtaining information about a target without directly interacting with the target’s systems. When you take this approach, your goal is to find and document public information about your target’s attack surface.

Exposed Credentials:

1. through OSINT
2. API keys, Creds, Jwts,

API Documentation: Helps you understand the target API.

- business insight and logic flaws

Improper asset management:

- eg: an endpoint being listed as deprecated/removed but still usable (aids in improper asset management finding)
- version information: clues on deprecated API endpoints

---

### google search + dorks

simply searching:

- start with simple google search about the API

dorks: docs,developers,dev, graphql:

```
intitle:"api" site:fb.com
inurl:"/api/v1" site:x
```

```
intitle:json site:'ebay.com'
```

|                                                         |                                                                                                                                                    |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Google Dorking Query**                                | **Expected results**                                                                                                                               |
| inurl:"/wp-json/wp/v2/users"                            | Finds all publicly available WordPress API user directories.                                                                                       |
| intitle:"index.of" intext:"api.txt"                     | Finds publicly available API key files.                                                                                                            |
| inurl:"/api/v1" intext:"index of /"                     | Finds potentially interesting API directories.                                                                                                     |
| ext:php inurl:"api.php?action="                         | Finds all sites with a XenAPI SQL injection vulnerability. (This query was posted in 2016; four years later, there are currently 141,000 results.) |
| intitle:"index of" api_key OR "api key" OR apiKey -pool | This is one of my favorite queries. It lists potentially exposed API keys.                                                                         |

---

### github search + dorks

- try automated git scanning tools that search for known API key names like from vendors such as google, AWS,..etc
- search in issues tab for exposed credentials
- extensions:

```
extension:json nasa
```

- web headers:

```
"authorization: Bearer"
```

swagger files: (can be imported into postman)

```
"filename:swagger.json"
```

---

## TruffleHog 

TruffleHog is a great tool for automatically discovering exposed secrets. You can simply use the following Docker run to initiate a TruffleHog scan of your target's Github.

```
 $ sudo docker run -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=target-name
```

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/01s4gYuoQmq9GgdZg4oG_TruffleHogv3.png)

In the above example, you can see that the org that was targeted was Venmo and the results of the scan indicate URLs that should be investigated for potentially leaked secrets. In addition to searching Github, TruffleHog can also be used to search for secrets in other sources like Git, Gitlab, Amazon S3, filesystem, and Syslog. To explore these other options use the "-h" flag. For additional information check out [https://github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog).

## **Shodan**

You can use Shodan to discover external-facing APIs and get information about your target’s open ports, making it useful if you have only an IP address or organization’s name to work from. Like with Google dorks, you can search Shodan casually by entering your target’s domain name or IP addresses; alternatively, you can use search parameters like you would when writing Google queries. The following table shows some useful Shodan queries.

|                                  |                                                                                                                                                                                                              |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Shodan Queries**               | **Purpose**                                                                                                                                                                                                  |
| hostname:"targetname.com"        | Using hostname will perform a basic Shodan search for your target’s domain name. This should be combined with the following queries to get results specific to your target.                                  |
| "content-type: application/json" | APIs should have their content-type set to JSON or XML. This query will filter results that respond with JSON.                                                                                               |
| "content-type: application/xml"  | This query will filter results that respond with XML.                                                                                                                                                        |
| "200 OK"                         | You can add "200 OK" to your search queries to get results that have had successful requests. However, if an API does not accept the format of Shodan’s request, it will likely issue a 300 or 400 response. |
| "wp-json"                        | This will search for web applications using the WordPress API.                                                                                                                                               |

### Shodan searches

just searching:

```
targetname
```

search for specific ports:

```
targetname  port:443
```

content-type application/json (often used with APIs):

```
"content-type: application/json"
```

if the target has word press in use:

```
"wp-json"
```

## Way Back Machine

can be used to test for improper asset management vulnerabilities via docs.
you may find the old documentation with the old/deprecated endpoints that might be still useable and have vulnerabilities present.
