---
title: web/quantum-market
platform: HTB
event: secfest26
category: web
tags: [business-logic, referral-abuse, credit-farming, fastapi, api-docs]
status: solved
difficulty: 2
---

# web/quantum-market

**Flag:** `HTB{15_th1s_1nfin1t3_m0n3y_gl1tch??_4cb42f060c026d60fc678fd7a53f92f4}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`.

## Summary

Quantum Market is a FastAPI shop. Users start with 0 credits and buy items with credits. The most expensive item is the "Market Manipulation Blueprint" for 1337 credits. Its content holds the flag, and the item is only shown to the buyer after the purchase.

The API docs at `/docs/` describe `POST /api/auth/register`, which takes an optional `referrer_id`. The description says it gives the referrer referral credits. The server does not check that the referee is a new or real user. Each new account that names an existing user as `referrer_id` gives that user 10 credits, so the credits can be farmed from accounts the attacker creates.

## Attack chain

1. **Read the docs.** `/openapi.json` lists the routes, and the register description mentions referral credits.
2. **Test one referral.** Register a referrer, then register a referee with `referrer_id` set to the referrer's username. The referrer's credits go from 0 to 10.
3. **Farm credits.** Repeat the referee registration until the referrer has at least 1337 credits. That takes 134 referees, which gives 1340 credits.
4. **Buy the blueprint.** `POST /api/market/purchase` with `item_id` 10 spends 1337 credits.
5. **Read the flag.** `GET /api/market/my-items` returns the purchased blueprint, and its `content` contains the flag.

## Steps

1. Run `solve.py`. It registers a referrer, reads the most expensive shop item, and registers referees until the referrer can afford it. Then it buys the item and reads the flag from `my-items`.
2. The solver prints the flag after `[+] Flag:`. The flag is `HTB{15_th1s_1nfin1t3_m0n3y_gl1tch??_4cb42f060c026d60fc678fd7a53f92f4}`.

## Sample output

Output of `python3 solve.py <target_ip> <target_port>` against the live instance. Pasted from the run, not written by hand.

```
[+] Credits after referrals: 1340
[+] Bought: Market Manipulation Blueprint (1337 credits)
[+] Flag:
HTB{15_th1s_1nfin1t3_m0n3y_gl1tch??_4cb42f060c026d60fc678fd7a53f92f4}
```

## Problems hit

- **The referrer_id is a username.** The docs call it an ID, but the server accepts a username and credits that account. A name that was not registered gives no bonus.
- **The farming is slow.** 134 sequential registrations take about 70 seconds. The solver runs them one at a time and does not use concurrency.
- **No other credit source was found.** The API has no other route that adds credits, and the leaderboard only shows balances. The referral farm was the only route tried.

## Defense

- **Require a real referral event.** Credit the referrer only after the referee completes a real action, such as a verified email, a first paid purchase, or an admin review.
- **Limit referrals per account and per IP.** Reject many sign-ups from one source or referring one account repeatedly.
- **Check the referrer exists and is not the new user.** Keep a record of who referred whom, and do not award credits to accounts that were created in bulk.
- **Hide sensitive item content until it is needed.** The flag was in the purchased item's `content`, which the buyer can read at any time.

## Lessons

- Business logic bugs need no special tools. The only tool is the documented API, used in a sequence the designer did not intend.
- Test each reward path for how much it gives and how cheaply it can be repeated. A small bonus repeated many times adds up.
- Read the schema descriptions. The phrase "earn referral credits" in `/openapi.json` pointed to the bug.
