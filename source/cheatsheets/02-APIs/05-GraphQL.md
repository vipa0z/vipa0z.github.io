### Locating The GraphQL Endpoint

- check for requests to `/graphql` or `/api/graphql` through recon/legitimate ops
- if there's no GUI, install [graphql playground](https://github.com/graphql/graphql-playground)

----
### Interacting with the API

IDENTIFYING TYPES
```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

query to find all fields for a  type:
for example  

```
{
  __type(name: "AddEmployee") {
    name
    kind
    fields {
      name
      type {
        name
        kind
        ofType {
          name
          kind
        }
      }
    }
  }
}
```

![[ss/Pasted image 20251130150108.png]]

query all fields for an object
```
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

use a query
```
{
  user(username: "test") {
    username
    password
  }
}

```

## mutations
```
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


## Introspection query
"general" introspection query that dumps all information about types, fields, and queries supported by the backend:
```
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

 visualize the schema using the tool [GraphQL-Voyager](https://github.com/graphql-kit/graphql-voyager)

In the demo, we can click `CHANGE SCHEMA` and select `INTROSPECTION`. After pasting the result of the above introspection query in the text field and clicking on `DISPLAY`, the backend's GraphQL schema is visualized for us. We can explore all supported queries, types, and fields:
![[ss/Pasted image 20251129233640.png]]
---
## Attacks:
IDOR
BLFA
Injections
DoS