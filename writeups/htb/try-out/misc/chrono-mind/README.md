---
title: misc/chrono-mind
platform: HTB
event: try-out
category: misc
tags: [path-traversal, llm, prompt-injection, secret-leak, rce]
status: solved
difficulty: 4
---

# misc/chrono-mind

**Difficulty:** 🌶️🌶️🌶️🌶️ (4/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip>:<target_port>`

## Summary

The app is a FastAPI service with a small LLM "knowledge base" chatbot. It has three flaws that chain together:

1. **Path traversal in the knowledge loader.** `POST /api/create` takes a `topic` and builds the file path as `repository/<topic>`, with no check on `..`. Sending `../config.py` loads the app's own `config.py` into the model context.
2. **Secret in the model context.** `config.py` holds `copilot_key`, a per-instance secret. Once the file is loaded, the LLM can be asked for it, and it answers with the value.
3. **Remote code execution behind the key.** `POST /api/copilot/complete_and_run` runs the submitted Python code with `python3`. It only checks that `copilot_key` matches.

The chain is: path traversal → LLM leaks the key → call the code endpoint with the key → read the flag with `/readflag`.

## Attack chain

- The first request after the container starts is slow. The first `/` took about 51 seconds, and the first `/api/create` call timed out with a 5-second limit. Later requests were fast.
- `/api/ask` answered in about 0.6 seconds once the server was warm. The leaked key came back as a quoted string inside a sentence, so the regex in the script was enough.
- `/api/copilot/complete_and_run` took about 40 seconds. The code-completion model runs on CPU, and the completed code is appended to the submitted code before it runs.
- The flag is printed twice in the output (the code's completion calls `/readflag` a second time). The script removes the duplicate lines.

## Steps

1. **Load `config.py`.** `POST /api/create` with `{"topic": "../config.py"}` returns `201`. The server also sets a `room` cookie. Keep the cookie for the next request.
2. **Leak the key.** `POST /api/ask` with a prompt that asks for the value of `copilot_key`, inside quotes. The model replies with a sentence that contains the key in quotes, for example `The exact value assigned to the copilot_key variable is "<key>"`. The script takes the first quoted string as the key.
3. **Run code.** `POST /api/copilot/complete_and_run` with the key and the code `import subprocess; print(subprocess.check_output(['/readflag']).decode())`. The server runs the code and returns the output in `result`. `/readflag` is setuid root and prints the flag.

The solve script does these three steps in one session and prints the flag.

The flag is `HTB{1nj3c73d_c0n73x7_c0p1l07_3x3cu73_REDACTED}`.

## Problems hit

- **Timeouts.** The first version used 5, 10, and 15 second timeouts. All three were too short for this server: the first request timed out during model load, and the code endpoint timed out at 15 seconds. The fix was to raise the timeouts to 120, 120, and 300 seconds.
- **Only the first line of context.** `/api/ask` keeps just the first line of the retrieved context (`context.split("\n")[0]`). In this case the first line of the matched chunk still contained the key, so the leak worked. If the chunk had split differently, the key line could have been dropped.

## Defense

- **Validate file paths.** Resolve `repository/<topic>` and check that the result stays inside `repository/`. Reject `..` and absolute paths. `os.path.realpath` plus a prefix check is enough here.
- **Do not put secrets in model context.** Anything loaded into the LLM context can be extracted with a prompt. The key should live outside the model's reach, and the check should not depend on a value the model can see.
- **Do not execute user code in the app's process.** The endpoint runs arbitrary Python as the app user. If code execution is needed, run it in a separate sandbox with no secrets and no access to the host's files.
- **Use an authorization check, not a shared string.** A single static key that is also readable through another endpoint is not an access control.

## Lessons

- Each flaw looks small by itself: a path that is not validated, a secret in a file, a key check on a dangerous endpoint. Together they give code execution.
- An LLM is not an access-control boundary. If a model can see a secret, a prompt can extract it.
