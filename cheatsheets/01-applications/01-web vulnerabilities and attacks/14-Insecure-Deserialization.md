## What is the impact of insecure deserialization?

The impact of insecure deserialization can be very severe because it provides an entry point to a massively increased attack surface. It allows an attacker to reuse existing application code in harmful ways, resulting in numerous other vulnerabilities, often remote code execution.

Even in cases where remote code execution is not possible, insecure deserialization can lead to privilege escalation, arbitrary file access, and denial-of-service attacks.

https://portswigger.net/web-security/deserialization/exploiting


## Manipulating serialized objects

, you can study the serialized data to identify and edit interesting attribute values. You can then pass the malicious object into the website via its deserialization process. This is the initial step for a basic deserialization exploit.

Broadly speaking, there are two approaches you can take when manipulating serialized objects. You can either edit the object directly in its byte stream form, or you can write a short script in the corresponding language to create and serialize the new object yourself. The latter approach is often easier when working with binary serialization formats.