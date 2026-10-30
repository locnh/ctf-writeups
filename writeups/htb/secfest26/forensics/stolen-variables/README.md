---
title: forensics/stolen-variables
platform: HTB
event: secfest26
category: forensics
tags: [aws, cloudtrail, cloudfront, amplify, dynamodb, leaked-credentials, config-js]
status: notes-only
difficulty: 2
---

# forensics/stolen-variables

**Flag:** not captured (answers only, no flag submitted)

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** none (manual steps)

## Summary

An AWS Amplify staging site exposed its `config.js` to the internet. The file held the access key of the deployer IAM user `niis-amplify-deployer`. From 2026-03-07 the attacker used that key from `115.166.125.51` to enumerate the account and then scan the `niis-identity-records` DynamoDB table.

The three artifacts are `cloudfront-access-logs.csv` (CloudFront logs for the Amplify domain), `event_history.csv` (CloudTrail management events) and `dynamodb.csv` (CloudTrail DynamoDB data events). The `config.js` body is not in the archive. Its key is inferred from the CloudTrail records, see the Steps.

## Attack chain

1. **Config exposure.** On 2026-03-07 at 15:32 UTC, `115.166.125.51` requested `/app/config.js` from `d209nq8eaf2s88.cloudfront.net`, with the referrer `https://staging.d209nq8eaf2s88.amplifyapp.com/index.html`.
2. **First use of the key.** At 15:36:18Z, the same IP used `AKIA453N4QOMFX23RUOL` (the `niis-amplify-deployer` user) from `aws-sdk-go-v2/1.3.2`. The first calls are a burst of about 50 read-only enumerations, most returning `AccessDenied`.
3. **DynamoDB enumeration.** From 15:36:37Z the attacker listed tables and limits, then ran `ListTables` and `ListBackups`.
4. **Scan.** At 15:51 to 15:53Z the attacker switched to `aws-cli/2.34.4`, called `ListBuckets` and `ListTables`, and ran `Scan` on `niis-identity-records` at 15:53:52Z.

## Steps

### 1. Map the artifacts

- `cloudfront-access-logs.csv`: 57 requests. The Amplify default domain shows up in `cs(Host)` and `Referer`.
- `event_history.csv`: 576 CloudTrail management events, newest first. 484 of them use `AKIA453N4QOMFX23RUOL`.
- `dynamodb.csv`: 26 DynamoDB data events, newest first.

### 2. Question 1: the Amplify application ID

The Amplify default domain is `<appId>.amplifyapp.com`. Every Amplify request in the CloudFront log uses `d209nq8eaf2s88.amplifyapp.com`, and the referrer uses `staging.d209nq8eaf2s88.amplifyapp.com`. The app ID is `d209nq8eaf2s88`.

### 3. Question 2: the IAM user whose credentials were exposed

Every event that uses the leaked key has `userIdentity` `arn:aws:iam::888750817624:user/niis-amplify-deployer`. The IAM user is `niis-amplify-deployer`.

### 4. Question 3: the AWS Access Key ID in `config.js`

The only `AKIA` key in the three artifacts is `AKIA453N4QOMFX23RUOL`. It is the key for `niis-amplify-deployer`, and the attacker used it right after loading `config.js`. The `config.js` body is not included, so this answer comes from matching the key to the attacker's activity rather than from reading the file.

### 5. Question 4: the source IP of the first use

The first event with the key, and every later event with it, comes from `115.166.125.51`. The same IP fetched `config.js` at 15:32Z. The answer is `115.166.125.51`.

Two other IPs are not part of the attack. `180.244.9.221` used `niis-developer-1` session keys on 2026-03-06 for normal table work, and `18.138.47.233` appears once with an `ASIA` key.

### 6. Question 5: the timestamp of the first use

The earliest event with the key is `2026-03-07T15:36:18Z`, in the format asked for.

### 7. Question 6: the first AWS API call

Several calls share the timestamp 15:36:18Z, and the export has one-second resolution, so the order inside that second cannot be read directly. The batch contains `GetRestApis`, `ListCertificates`, `GetClientCertificates`, `GetDomainNames`, `GetSdkTypes`, `GetUsagePlans`, `GetVpcLinks`, `GetApiKeys`, `GetCallerIdentity`, `ListApps`, `GetAccount` and `ListGraphqlApis`.

The answer is `sts:GetCallerIdentity`. It is the only call in the batch that succeeds, and an attacker normally checks the credentials first. The other candidate, reading the export bottom-up, is `appsync:ListGraphqlApis`. This answer depends on the tie-break, so it is less certain than the others.

### 8. Question 7: the DynamoDB table

The attacker's DynamoDB data events all use `niis-identity-records`. The `Scan` at 15:53:52Z is the one that reads the table. The answer is `niis-identity-records`.

## Sample output

No solve script. The answers come from the steps above. Output of `python3 -I -c "import csv,sys; rows=list(csv.DictReader(open(sys.argv[1]))); ak=[r for r in rows if r['AWS access key']=='AKIA453N4QOMFX23RUOL']; print(min(r['Event time'] for r in ak))" <path>/event_history.csv`, run from a scratch folder:

```
2026-03-07T15:36:18Z
```

## Problems hit

- **`config.js` is missing.** The archive has no copy of the file, so the key cannot be read from it. Matching the key to the attacker's first use is the only route here.
- **Same-second ordering.** The batch at 15:36:18Z has 12 events in one second. The export does not keep the order inside that second, so the first call is not certain.
- **The `cs(User-Agent)` column name.** The CSV header has a backslash-escaped name, so `csv.DictReader` does not find it. Indexing by column position works.
- **Look-alike activity.** `niis-developer-1` used the same DynamoDB table on 2026-03-06, with different credentials and a browser user agent. It is not part of the attack.

## Defense

- **Keep credentials out of client-side config.** A `config.js` served to the browser should not hold an IAM access key. Use short-lived credentials, or keep the key on the server.
- **Restrict the deployer role.** `niis-amplify-deployer` can run DynamoDB `Scan` on the identity table. Give deploy roles only the calls they need.
- **Alert on new source IPs and SDKs.** The key moved from a web session to `aws-sdk-go-v2` and then `aws-cli` from a new IP.
- **Restrict staging sites.** The staging domain was public and served the config.

## Lessons

- A key found in a public file is only half the story. Matching it to CloudTrail shows where it was used, from which IP, and what was taken.
- CloudTrail's one-second timestamps can leave the order of a burst unclear. Say so when a question depends on that order.
