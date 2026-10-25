---
title: blockchain/notademocraticelection
platform: HTB
event: try-out
category: blockchain
tags: [solidity, foundry, abi-encodepacked, hash-collision, access-control, voting]
status: solved
---

# blockchain/notademocraticelection

**Flag:** `HTB{REDACTED}`

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <info_port> <rpc_port>`. The challenge has two ports, so the usual `<target_ip> <target_port>` form does not apply. The info port returns the key and the contract address, and the RPC port is an Anvil node.

## Summary

The goal is to make the party `CIM` win the election. The contract declares a winner once a party has at least `1000e18` votes. The vote weight of a voter comes from a deposit, and the deposit is stored under a key built with `abi.encodePacked(name, surname)`. That key concatenates the two strings with no separator. Eligibility to vote is checked by a different key, the pair `(name, surname)`. Because the two keys do not match, one deposit can back several identities, and each identity can vote with the same weight.

The setup deposits 100 ether for `Satoshi Nakamoto`. The weight for that key is therefore `100e18`. Splitting `SatoshiNakamoto` at any other position gives a new identity with the same key. Each such identity can deposit with zero value and vote for `CIM`. Each vote adds `100e18`, so ten votes reach `1000e18` and set the winner.

## Source review

The challenge has three contracts. `Setup.sol` deploys the target, makes the first deposit, and exposes `isSolved()`, which checks `winner == "CIM"`. The main logic is in `NotADemocraticElection.sol`:

- `voters` is keyed by `getVoterSig(name, surname)`, which is `abi.encodePacked(name, surname)`. That key has no separator, so `("Satoshi", "Nakamoto")` and `("SatoshiNaka", "moto")` produce the same key.
- `uniqueVoters` is keyed by the pair `(name, surname)`. It is used only to check that the caller owns the identity. Two different pairs with the same concatenation are two identities.
- `depositVoteCollateral` adds `msg.value` to `voters[sig].weight` even when the value is zero, and it registers the caller under the new pair.
- `vote` uses `voters[sig].weight` as the vote weight. It adds that weight to the party, and then calls `checkWinner`.
- Nothing stops one identity from voting more than once. Every vote adds the full weight again.

The bug is the inconsistent key. The weight is stored under one key, and the right to vote is granted under another. Each new split is a new voter that inherits the weight of the original deposit.

## Steps

1. Ask the info port for the connection information (menu option 1). It returns the player's private key, the address, the target contract, and the setup contract. Do not use option 2, which restarts the instance.
2. For every split of `SatoshiNakamoto` except the original `Satoshi`/`Nakamoto` split (positions 1 to 11, skipping 7), call `depositVoteCollateral(name, surname)` with no value. This registers the caller for that pair. The weight does not change.
3. For each of those splits, call `vote(0x434d, name, surname)`, where `0x434d` is `CIM` as `bytes3`. Each vote adds `100e18`.
4. After ten votes the total for `CIM` is `1000e18`, and `winner()` becomes `CIM`.
5. Ask the info port for option 3. It returns the flag.

The solve script runs steps 1 to 5 with `cast send` from Foundry. The `cast send` calls are sent in sequence. Each one waits for its receipt.

## Observations

- Before the attack, `winner()` was empty and `getVotesCount(CIM)` was 0. The player address had 1 ETH.
- Each deposit cost about 50k gas and each vote about 59k gas. The whole attack needs no ether beyond gas, because the weight comes from the setup deposit.
- Every transaction succeeded, and `VoterDeposited` and `Voted` events were emitted for each one.
- The info port returned the flag after the last vote: `HTB{REDACTED}`.
- After the run, the RPC node reported that the contract had no code at the target address. The instance seems to have been reset after the flag was issued, so the on-chain state could not be checked again. The flag from the info port is the proof of the solve.

## Problems hit

- **Port 41625 looked silent.** A raw socket to it returned no banner. It is the RPC node, not the menu. A `eth_chainId` request returned `0x7a69` (31337, Anvil), which confirmed it.
- **`cast` was not installed.** The script depends on Foundry's `cast`. I installed it with `brew install foundry` (v1.8.6).
- **The final state check failed.** See the last observation above. The flag was already returned, so this did not block the solve.

## Defense

- **Use one key for everything.** The weight and the right to vote must be stored under the same identity. Use `keccak256(abi.encode(name, surname))`, or better, use the caller address as the identity, not free-form strings.
- **Do not use `abi.encodePacked` on dynamic types in a key.** Packed encoding of two strings is ambiguous. Any two splits with the same concatenation collide. This is the "hash collision" the flag name hints at.
- **Let each voter vote once.** Track a `hasVoted` flag per identity. Without it, a single deposit can be used any number of times.
- **Reject zero-value deposits that add nothing.** A deposit that does not change the weight should not register a new voter.

## Lessons

- The logic error is in the mismatch between two keys, not in the arithmetic. Compare every mapping that uses the same concept, and check that they use the same key.
- A hash collision does not have to break a cryptographic hash. An ambiguous encoding is enough.
- When the code path needs a value that exists only on-chain, read the contract's state first. Here, the `winner` and `getVotesCount` reads before the attack were the baseline.
