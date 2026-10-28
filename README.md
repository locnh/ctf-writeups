# CTF notes

Writeups, attack technique notes, and defensive notes from CTF challenges.

## Layout

- `writeups/<platform>/<event>/<challenge>/`: writeup (`README.md`) and solve artifacts (`artifacts/`).
- `writeups/pwnbox/`: pwnbox.io challenges.
- `templates/writeup.md`: template for new writeups.

## Difficulty

Each writeup has a difficulty from 1 to 5, shown as chili peppers (🌶️) in the table and in the writeup header. The rating is our own subjective judgment of how hard the challenge was for us, not the platform's rating.

| Level | Icon | Meaning |
|---|---|---|
| 1 | 🌶️ | Easy |
| 2 | 🌶️🌶️ | Moderate |
| 3 | 🌶️🌶️🌶️ | Medium |
| 4 | 🌶️🌶️🌶️🌶️ | Hard |
| 5 | 🌶️🌶️🌶️🌶️🌶️ | Very hard |

## Status

| Icon | Meaning |
|---|---|
| 🏁 | Solved (flag captured) |
| 🤖 | Ships an automatic solve script (`solve.py`) |
| 💪 | Manual: steps guideline only |

## Writeups

### secfest26

| Platform | Event | Challenge | Category | Difficulty | Status | Auto solve |
|---|---|---|---|---|---|---|
| HTB | secfest26 | [frontdesk](writeups/htb/secfest26/web/frontdesk/README.md) | web | 🌶️ (1/5) | 🏁 | 🤖 |
| HTB | secfest26 | [open-invitation](writeups/htb/secfest26/web/open-invitation/README.md) | web | 🌶️ (1/5) | 🏁 | 🤖 |
| HTB | secfest26 | [checkout](writeups/htb/secfest26/web/checkout/README.md) | web | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | secfest26 | [dns-dossier](writeups/htb/secfest26/web/dns-dossier/README.md) | web | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | secfest26 | [sr-network](writeups/htb/secfest26/web/sr-network/README.md) | web | 🌶️🌶️🌶️ (3/5) | 🏁 | 💪 |

### try-out

| Platform | Event | Challenge | Category | Difficulty | Status | Auto solve |
|---|---|---|---|---|---|---|
| HTB | try-out | [prison-pipeline](writeups/htb/try-out/misc/prison-pipeline/README.md) | misc | 🌶️🌶️🌶️🌶️ (4/5) | 🏁 | 🤖 |
| HTB | try-out | [locked-away](writeups/htb/try-out/misc/locked-away/README.md) | misc | 🌶️🌶️🌶️ (3/5) | 🏁 | 🤖 |
| HTB | try-out | [dynastic](writeups/htb/try-out/crypto/dynastic/README.md) | crypto | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | try-out | [blessed](writeups/htb/try-out/crypto/blessed/README.md) | crypto | 🌶️🌶️🌶️🌶️ (4/5) | 🏁 | 🤖 |
| HTB | try-out | [notademocraticelection](writeups/htb/try-out/blockchain/notademocraticelection/README.md) | blockchain | 🌶️🌶️🌶️ (3/5) | 🏁 | 🤖 |
| HTB | try-out | [dynamic-paths](writeups/htb/try-out/code/dynamic-paths/README.md) | code | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | try-out | [character](writeups/htb/try-out/misc/character/README.md) | misc | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | try-out | [chrono-mind](writeups/htb/try-out/misc/chrono-mind/README.md) | misc | 🌶️🌶️🌶️🌶️ (4/5) | 🏁 | 🤖 |
| HTB | try-out | [hidden-path](writeups/htb/try-out/misc/hidden-path/README.md) | misc | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | try-out | [stop-drop-roll](writeups/htb/try-out/misc/stop-drop-roll/README.md) | misc | 🌶️ (1/5) | 🏁 | 🤖 |
| HTB | try-out | [regularity](writeups/htb/try-out/pwn/regularity/README.md) | pwn | 🌶️🌶️🌶️ (3/5) | 🏁 | 🤖 |
| HTB | try-out | [abyss](writeups/htb/try-out/pwn/abyss/README.md) | pwn | 🌶️🌶️🌶️ (3/5) | 🏁 | 🤖 |
| HTB | try-out | [getting-started](writeups/htb/try-out/pwn/getting-started/README.md) | pwn | 🌶️ (1/5) | 🏁 | 🤖 |
| HTB | try-out | [labyrinth](writeups/htb/try-out/pwn/labyrinth/README.md) | pwn | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | try-out | [void](writeups/htb/try-out/pwn/void/README.md) | pwn | 🌶️🌶️🌶️🌶️🌶️ (5/5) | 🏁 | 🤖 |
| HTB | try-out | [router-web](writeups/htb/try-out/pwn/router-web/README.md) | pwn | 🌶️🌶️🌶️🌶️🌶️ (5/5) | 🏁 | 🤖 |
| HTB | try-out | [jailbreak](writeups/htb/try-out/web/jailbreak/README.md) | web | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | try-out | [timekorp](writeups/htb/try-out/web/timekorp/README.md) | web | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | try-out | [flag-command](writeups/htb/try-out/web/flag-command/README.md) | web | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | try-out | [guild](writeups/htb/try-out/web/guild/README.md) | web | 🌶️🌶️🌶️ (3/5) | 🏁 | 🤖 |
| HTB | try-out | [labyrinth-linguist](writeups/htb/try-out/web/labyrinth-linguist/README.md) | web | 🌶️🌶️🌶️ (3/5) | 🏁 | 🤖 |
| HTB | try-out | [htb-proxy](writeups/htb/try-out/web/htb-proxy/README.md) | web | 🌶️🌶️🌶️🌶️ (4/5) | 🏁 | 🤖 |
| HTB | try-out | [blueprint-heist](writeups/htb/try-out/web/blueprint-heist/README.md) | web | 🌶️🌶️🌶️🌶️🌶️ (5/5) | 🏁 | 🤖 |
| HTB | try-out | [omniwatch](writeups/htb/try-out/web/omniwatch/README.md) | web | 🌶️🌶️🌶️🌶️ (4/5) | 🏁 | 🤖 |
| HTB | try-out | [an-unusual-sighting](writeups/htb/try-out/forensics/an-unusual-sighting/README.md) | forensics | 🌶️🌶️ (2/5) | 🏁 | 💪 |
| HTB | try-out | [silicon-data-sleuthing](writeups/htb/try-out/forensics/silicon-data-sleuthing/README.md) | forensics | 🌶️🌶️🌶️🌶️ (4/5) | 🏁 | 💪 |
| HTB | try-out | [phreaky](writeups/htb/try-out/forensics/phreaky/README.md) | forensics | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | try-out | [flagcasino](writeups/htb/try-out/reversing/flagcasino/README.md) | reversing | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | try-out | [lootstash](writeups/htb/try-out/reversing/lootstash/README.md) | reversing | 🌶️🌶️ (2/5) | 🏁 | 🤖 |
| HTB | try-out | [dont-panic](writeups/htb/try-out/reversing/dont-panic/README.md) | reversing | 🌶️🌶️🌶️ (3/5) | 🏁 | 🤖 |
| HTB | try-out | [tunnelmadness](writeups/htb/try-out/reversing/tunnelmadness/README.md) | reversing | 🌶️🌶️🌶️ (3/5) | 🏁 | 🤖 |
| HTB | try-out | [satellite-hijack](writeups/htb/try-out/reversing/satellite-hijack/README.md) | reversing | 🌶️🌶️🌶️🌶️ (4/5) | 🏁 | 🤖 |
