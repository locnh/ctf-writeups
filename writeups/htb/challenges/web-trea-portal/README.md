---
title: web/trea-portal
platform: HTB
event: challenge
category: web
tags: [xpath-injection, type-confusion, fastify, jwt, query-parser]
status: solved
difficulty: 2
---

# web/trea-portal

**Flag:** `HTB{5ac2f265_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run as `python3 solve.py <target_ip> <target_port>`.

## Summary

TreaPortal is a Fastify app backed by an XML file instead of a database. `src/db/init.ts` writes `users.xml` at first boot, with an `admin` user that holds the flag and a bcrypt-hashed random password.

`GET /api/user/` takes a `username` query parameter, requires a valid JWT, and returns the matching user record. It only rejects a different username when the value is a **string**. A repeated query parameter makes Fastify pass an **array**, so the check is skipped. The XPath injection filter then runs `Array.prototype.includes` on that array, which compares whole elements instead of substrings, so a quoted payload hidden inside a longer element passes. The joined array is interpolated into `//user[username='...']`, and an `or 1=1` predicate returns the admin record, flag included.

## Attack chain

1. **Register.** `POST /api/auth/register` accepts any `@trea.htb` email and returns a JWT with `role: employee`.
2. **Baseline.** `GET /api/user/?username=<self>` returns the own record (empty flag). `?username=admin` returns 403, because it is a string that differs from the token.
3. **Type confusion.** Send `?username=x&username=y`. Fastify's query parser turns repeated keys into `["x","y"]`, so `typeof username === 'string'` is false and the 403 branch never runs.
4. **Filter bypass.** `looksLikeXPathInjection` calls `input.includes(pattern)` on the array. For an array, `includes` is an exact element match, not a substring match. An element containing quotes, `or`, and parentheses does not equal any blacklisted pattern, so it passes.
5. **XPath injection.** The array is stringified with commas when interpolated: `username='x,y' or 1=1 or username=''`. The condition is true for every user, and `xpath.select1` returns the first node in document order, which is `admin`.
6. **Flag.** The response contains the admin record, including `flag`.

### Code analysis

The relevant code is three small files in `src/web_treaportal/src/`.

`routes/user.ts` (the `GET /api/user/` handler):

```ts
const { username } = req.query as any
const tokenPayload = req.user as IJwtPayload

if (typeof username === 'string' && username !== tokenPayload.username) {
    return res.status(403).send({ err: 'Access denied' })
}
const user = await getUserByUsername(username)
```

The ownership check only runs for a `string`. Fastify's default query parser turns a repeated key into an array, so `username` can reach `getUserByUsername` as `["x", "y"]` and the 403 branch is skipped. The code does not normalize the type or validate it with a schema.

`services/userService.ts` (the XPath guard and query):

```ts
function looksLikeXPathInjection(input: string): boolean {
    const blacklist = ["'", ';', 'or', 'and', ')', "(", "/" , "doc"] ;
    return blacklist.some(pattern => input.includes(pattern)) ;
}

export async function getUserByUsername(username: any): Promise<IUser | null> {
    if (looksLikeXPathInjection(username)) throw new Error('bad')
    const doc = await getDoc()
    const node = xpath.select1(`//user[username='${username}']`, doc as any)
    return nodeToUser(node)
}
```

Two things combine here:

- `input.includes(pattern)` is called on the value as received. For a string it is a substring test, which catches `'` and `or`. For an array it is `Array.prototype.includes`, an exact-element test. `"x"` and `"y' or 1=1 or username='"` do not equal any blacklisted pattern, so the array passes.
- The template literal `${username}` stringifies the array with commas, giving `x,y' or 1=1 or username=''`. The comma lands inside the first string literal, so the predicate stays valid XPath and `or 1=1` makes it true for every user.

`db/init.ts` seeds `users.xml` with `admin` as the first `<user>` and puts the flag in its `<flag>` element. `xpath.select1` returns the first match in document order, so the injected predicate returns the admin record. Self-registered users are created by `createUser` with `<flag></flag>`, so the flag is only reachable through the injection.

## Steps

1. **Confirm the target is up and register an account.**

   ```
   $ curl -s -X POST http://<target>/api/auth/register \
       -H 'Content-Type: application/json' \
       -d '{"username":"u1","email":"u1@trea.htb","password":"Passw0rd!"}'
   {"jwt":"eyJhbGciOiJIUzI1NiIs..."}
   ```

2. **Check the normal behaviour.** A string username other than the caller's returns 403; the caller's own username returns the record with an empty flag.

   ```
   $ curl -s -H "Authorization: Bearer $JWT" 'http://<target>/api/user/?username=admin'
   {"err":"Access denied"}
   ```

3. **Send the injection.** Repeat the `username` parameter. The payload element is `y' or 1=1 or username='`; the leading `x` element puts the comma produced by the array join inside the first string literal, so the expression stays valid.

   ```
   $ python3 solve.py <target_ip> <target_port>
   ```

4. **Read the flag** from the `flag` field of the returned admin record.

## Sample output

Output of the documented solve command against the live instance, with the flag masked.

```
$ python3 solve.py 154.57.164.66 35833
HTB{5ac2f265_REDACTED}
```

## Problems hit

- A repeated query parameter is required. A single value is a string and hits the 403 branch. The array path needs at least two occurrences of `username`.
- The array join inserts a comma between elements, so the raw injection has to keep that comma syntactically valid. Putting a harmless first element (`x`) inside the first string literal, `username='x,y' ...`, does it.
- The blacklist looks effective when read as a string filter. It only becomes a bypass because the same code runs on an array, where `includes` means exact element equality.
- The flag is only present on the admin record; self-registered users get an empty `flag` element, so there is nothing to leak without the injection.

## Defense

- Validate the query with a Fastify schema (`username: { type: 'string' }`) so repeated parameters are rejected before the handler runs. Normalize with `String(username)` before comparing, or reject any non-string type explicitly.
- Do not build XPath expressions by concatenation. Use variables: `xpath.select1("//user[username=$u]", doc, { u: username })`.
- Treat blacklists as defense in depth, not as the control. The primary fix is parameterized queries and strict input types.
- Do not serialize the flag into records that the API can return for other users.
- Use a real database with parameterized queries instead of a file that is re-parsed and rewritten on every request.

## Lessons

- Query parsers are a type boundary. A value that is a `string` in one request can be an `array` or `object` in another, and checks written for the string case silently disappear.
- `Array.prototype.includes` and `String.prototype.includes` have different semantics. Code that filters input without knowing its type can be bypassed by changing the type.
- Injection filters written against one syntactic shape (quotes, `or`) do not survive a change in how the value is assembled.
