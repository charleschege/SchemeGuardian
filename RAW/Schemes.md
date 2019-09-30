### Schemes

```
[scheme]:[url]:[port]/[query_string]
```

***
example:

For schemes that are not a base
`
https:0000:443/schemeguardian/
`

For schemes that are a base
`
cookie:0000:3030/identifier?cookie=nnmlblblkglguk^£%$
`

This query returns data with headers that have custom response codes and a body with the identifier and more information like permissions, directory access, etc.

---
#### Features
1. **Directory Guards (`dir:`)**
2. **Port Guards**
For example port 443 is only subject to https connections, require override to ensure it happens even in the binary so that it can return an error if the `.toml` file has been misconfigured or changed maliciously.
3. **rwx ( `perm:`) Guards** 
These check for Create, Read, Write, Append, Modify, Delete permissions

---