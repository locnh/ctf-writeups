---
title: secure-coding/logics-business
platform: HTB
event: secfest26
category: secure-coding
tags: [business-logic, negative-amount, arbitrage, exchange-rate, editor-api, patching]
status: solved
difficulty: 3
---

# secure-coding/logics-business

**Flag:** `HTB{FR0NT_4ND_B4CK_TH3_BU51N355_3Y3_D035_533#!#$}`

**Difficulty:** 🌶️🌶️🌶️ (3/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`. It replaces `blueprints/routes.py` with `artifacts/routes_patched.py` through the editor API, restarts the service, and prints the flag from `/editor_api/verify`.

## Summary

The app is a Flask banking API (SQLite, JWT) with a React frontend. nginx serves the API under `/api` and a web editor at `/` (`HTB Editor`). The editor reads and writes files under `/www/application` through `/editor_api/*` and has a `/verify` endpoint that runs the checker. The task is to find and fix the business-logic bugs in `blueprints/routes.py`. `/verify` returns the flag once the bugs are fixed.

The bugs are numeric:

- `send_money`, `exchange`, and `request_loan` accept negative amounts. A negative transfer takes money from the recipient.
- `EXCHANGE_RATES` is not reciprocal (`0.72 × 1.39 ≈ 1.0008`), so a round trip makes a profit.
- `promote` deducts 1000 Schmeckle without checking the balance.

The patched file fixes all of them. The flag is in `/flag.txt` on the target. The shipped `challenge/flag.txt` is a placeholder.

### Vulnerable code

Original `blueprints/routes.py`, from the archive.

The exchange rates are not reciprocal, so a round trip gains about 0.08%:

```python
EXCHANGE_RATES = {
    'Schmeckle': {'Blemflark': 0.72, 'Schmeckle' : 1},
    'Blemflark': {'Schmeckle': 1.39, 'Blemflark' : 1}
}
```

`send_money` only checks that `amount` converts to a float. It never checks the sign, so a negative amount moves money from the recipient to the sender:

```python
    try:
        amount = float(amount)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid amount.'}), 400
    
    if not recipient_username or not amount or not currency:
        return jsonify({'success': False, 'message': 'Recipient, amount, and currency are required.'}), 400
        
    ...
    if currency == 'schmeckle':
        if sender.schmeckle_balance < amount:
            return jsonify({'success': False, 'message': 'Insufficient Schmeckle balance.'}), 400
        sender.schmeckle_balance -= amount
        recipient.schmeckle_balance += amount
```

`exchange_currency` rejects `amount <= 0`, which blocks negatives, but `nan` passes both that check and `not amount`, so the balance becomes `nan`:

```python
    if not from_currency or not to_currency or not amount:
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400
    
    if amount <= 0:
        return jsonify({'success': False, 'message': 'Amount must be positive.'}), 400
```

`request_loan` only checks `not amount`, so a negative loan is accepted:

```python
    if not amount:
        return jsonify({'success': False, 'message': 'Valid loan amount is required.'}), 400
```

`promote` deducts 1000 Schmeckle without checking the balance:

```python
    user.role = 'pending_promotion'
    user.schmeckle_balance -= 1000  # Deduct 1000 Schmeckle for promotion
```

## Attack chain

1. **Register and log in.** Create a user with `POST /api/register` and `POST /api/login`. Every new account starts with 10000 Schmeckle and 5000 Blemflark.
2. **Round-trip profit.** `POST /api/exchange` with `9999 Schmeckle → Blemflark`, then the returned Blemflark amount back to Schmeckle. The balance grows by about 0.08% per round trip.
3. **Negative transfer.** `POST /api/send_money` with `amount: -500`. The sender gains 500 and the recipient loses 500, because the code never checks the sign.
4. **Other money paths.** A negative loan request is accepted, and `POST /api/profile/promote` runs with any balance, which can make it negative.
5. **Fix.** Reject non-finite and non-positive amounts, make the reverse rate `1/0.72`, and check the balance before promotion. `artifacts/routes_patched.py` has these changes. The editor's `/verify` then passes.

## Steps

1. Run the solve script against the instance:

   ```
   python3 solve.py <target_ip> <target_port>
   ```

2. The script does the following:
   - Reads `blueprints/routes.py` through `GET /editor_api/file`.
   - If the file differs from `artifacts/routes_patched.py`, writes the patched version through `POST /editor_api/save`, with `client_md5` set to the MD5 of the current content. A mismatch returns "Conflict detected".
   - Calls `POST /editor_api/restart`.
   - Calls `GET /editor_api/verify` and prints the flag from the `flag` field.
3. Running the script again is safe. It prints `already patched` and goes straight to the restart and verify steps.

The patch is `artifacts/routes_patched.py`, with md5 `eb77b08661fb1fb9a52226f2842fdd92` after it is written. Diff against the original `blueprints/routes.py`:

- `import math` and an `is_valid_amount()` helper that rejects NaN, infinity, and values ≤ 0. It is used in `send_money`, `exchange_currency`, and `request_loan`.
- `SCHMECKLE_TO_BLEMFLARK = 0.72`, with the reverse rate set to `1 / SCHMECKLE_TO_BLEMFLARK`.
- `promote` returns 400 when `schmeckle_balance < 1000`.

## Sample output

Output of the documented solve command, as printed. Paste the real output from running it; do not write it by hand.

```
[*] patching blueprints/routes.py (current md5 310a7ba74bc1b3abbecb8c64fc482016)
[+] saved: {"md5":"eb77b08661fb1fb9a52226f2842fdd92","message":"File saved successfully"}
[*] restart: 200 {"message":"Server restarted successfully!"}
[+] Flag: HTB{FR0NT_4ND_B4CK_TH3_BU51N355_3Y3_D035_533#!#$}
```

## Problems hit

- **Stale instances.** The first notes pointed at instances that had been replaced or were no longer reachable. The endpoint used for this writeup is a fresh instance, where `blueprints/routes.py` still matched the archive (md5 `310a7ba…`) before the script ran.
- **First attempt: fix everything, and fail.** On the first day I patched every business-logic bug found in the app in one go. That set included send and exchange fees, a server-side 40% exchange limit, atomic balance updates, settlement on account closure, and the other fixes listed in the day-1 report (`report.md`, kept locally and not published). `/verify` kept returning `Vulnerability check failed — the security issue has not been resolved.` I judged this to be overkill, and the extra changes did not help the check pass.
- **Second attempt: fix one bug at a time and check.** The next day I went back to the minimal approach: fix each bug, then check `/verify` after the change. The fixes that made `/verify` pass are the ones in `artifacts/routes_patched.py`: amount validation, the reciprocal rate, and the promotion balance check. This is the patch the script applies.
- **SMB was not needed.** The editor API writes the same files under `/www/application`, so the SMB share in `note.md` was not mounted. Port 445 was not reachable from the test machine.
- **Editor 400 on failure.** `/editor_api/verify` returns 400 with `{"error": "Vulnerability check failed ..."}` until the bugs are fixed. The script treats 400 as a failure and exits with status 1.

## Defense

- Validate amounts on every money path: reject non-finite, zero, and negative values before any balance changes.
- Use one exchange rate and derive the reverse rate from it. Check that a round trip cannot return more than it started with.
- Check the balance before any debit, including fees and promotion costs.
- Enforce business limits (such as the 40% exchange limit) on the server, not only in the frontend.
- Do not expose a file editor on a service that serves the app. A write path to the source code turns any logic bug into a code change by anyone who can reach it.

## Lessons

- Numeric business logic fails at the boundaries: sign, NaN and infinity, and rates that are almost but not exactly reciprocal. Test those values first.
- A fixed patch can be checked against the same inputs before it is deployed. Verify each rule separately, and keep the output of each run.
- Get the verifier's behaviour from the platform before writing a larger fix. Testing small changes against the checker shows which one it needs.
