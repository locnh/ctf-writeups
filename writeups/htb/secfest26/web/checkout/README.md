---
title: web/checkout
platform: HTB
event: secfest26
category: web
tags: [webhook, signature-bypass, authentication-bypass, payment]
status: solved
difficulty: 2
---

# web/checkout

**Flag:** `HTB{W3bh00k_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`.

## Summary

The app is a vendor portal (Express, Node 20). A new vendor must pay a 149 EUR registration fee before the account is activated. The card checkout is disabled ("maintenance"), so the payment is never completed by the user. The payment is confirmed by a webhook, `POST /webhooks/payment/confirm`.

The webhook checks the `X-Signature` HMAC only when that header is present:

```js
if (signature) {
  if (!verifySignature(signature, rawBody || Buffer.from(""))) {
    return { statusCode: 400, message: "invalid signature" };
  }
  markPaid(payment.paymentId);
  return { statusCode: 200, message: "payment processed" };
}
markPaid(payment.paymentId);   // reached with no signature header
```

With no header, the code runs `markPaid` without any check. `GET /vendor/payment/status?paymentId=...` shows the flag when a payment is `PAID`.

Relevant code, from `Checkout/controllers/webhook.js` and `Checkout/controllers/payment.js`:

- `webhook.js`: the signature check is optional. An invalid signature returns 400, but a missing one is accepted.
- `payment.js`: the flag from `FLAG_PATH` is shown for any `PAID` payment, with no check of the viewer.
- `config.js`: `WEBHOOK_SECRET` is random per process, so a forged signature cannot be computed. It is not needed.

### Vulnerable code

The signature check is skipped when the header is missing. From `private/htb/secfest26/web-checkout/src/Checkout/controllers/webhook.js` (lines 40-50):

```js
  if (signature) {
    if (!verifySignature(signature, rawBody || Buffer.from(""))) {
      return { statusCode: 400, message: "invalid signature" };
    }

    markPaid(payment.paymentId);
    return { statusCode: 200, message: "payment processed" };
  }

  markPaid(payment.paymentId);
  return { statusCode: 200, message: "payment processed" };
```

The flag is returned for any `PAID` payment. From `private/htb/secfest26/web-checkout/src/Checkout/controllers/payment.js` (lines 19-23):

```js
  let flagHtml = "";
  if (payment.status === "PAID") {
    const flag = fs.readFileSync(FLAG_PATH, "utf8").trim();
    flagHtml = `<h3>Flag</h3><pre>${flag}</pre>`;
  }
```

## Attack chain

1. **Register a vendor.** `POST /vendor/register` creates the account, and the response shows its `pay_...` payment ID.
2. **Confirm the payment without a signature.** `POST /webhooks/payment/confirm` with JSON `{"event":"payment.confirmed","status":"PAID","paymentId":"<id>","confirmationRef":"..."}` and no `X-Signature` header. The server responds `payment processed`.
3. **Read the flag.** `GET /vendor/payment/status?paymentId=<id>` shows the payment as PAID, and the flag is in the page.

### Trial and error

Steps tried before the flag was found, in order:

1. I downloaded the source first and read `app.js` (routes), `controllers/webhook.js`, `controllers/payment.js`, `models.js`, `config.js` and the Dockerfile. My first idea was to forge the HMAC, which needs `WEBHOOK_SECRET`.
2. `WEBHOOK_SECRET` is random at startup, so forging a valid signature was not possible. I then read `handlePaymentConfirmation` again. The signature check sits inside `if (signature)`, so the path without the header skips it.
3. On the live instance, I registered a vendor. The dashboard showed payment `pay_15a92bf65c5b`, and the Pay button was disabled ("Payment service maintenance").
4. I sent the unsigned webhook, which returned `payment processed`. The status page then showed `PAID` and the flag.

I did not send a wrong signature to the live server, so the rejection path is from reading the code only.

## Steps

1. Run `solve.py`. It registers a random vendor, reads the payment ID from the dashboard, sends the unsigned webhook, and prints the flag from the status page.
2. The flag is printed as `[+] Flag:`. The flag is `HTB{W3bh00k_REDACTED}`.

## Sample output

Output of `python3 solve.py <target_ip> <target_port>` against the live instance, with the flag masked. Pasted from the run, not written by hand.

```
[*] Vendor registered, payment pay_cf5bc968dcc5
[*] Webhook: payment processed
[+] Flag:
HTB{W3bh00k_REDACTED}
```

## Problems hit

- **The card checkout is disabled.** The dashboard shows "Payment service maintenance" and the Pay button is disabled, so the payment cannot be completed through the UI. The webhook does not need the UI, so this was not a blocker.
- **The webhook secret is unknown.** `WEBHOOK_SECRET` is random at startup, so a valid HMAC cannot be made. The bypass is that the signature check is skipped when the header is absent, and the secret is not needed.

## Defense

- **Require the signature.** Reject any webhook without a valid `X-Signature`. Do not treat a missing signature as trusted.
- **Verify before acting.** Check the HMAC over the raw body, with a constant-time comparison, before any state change. Here the check was optional, and the code still changed state when it was absent.
- **Authenticate the payment provider's callback.** Use a shared secret for the provider and verify the timestamp as well, to block replays.
- **Confirm payment state from the provider.** Do not mark an account paid because a callback says so. Look the payment up at the provider before activation.

## Lessons

- A check that runs only when a value is present is not a check. Any control that the attacker can skip by omitting a field is a bypass.
- Read the code path for the empty or missing case, not only the case with valid input.
- Some values are easy to recover from a page (the payment ID here), so the flow only needs one unauthenticated step to finish.
