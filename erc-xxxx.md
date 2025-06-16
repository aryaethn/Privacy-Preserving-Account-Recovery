---
eip: 0
title: ZK Privacy-Preserving Account Recovery
author: Aryaethn <aryaethn@gmail.com>, 4rdiii <agh1994@gmail.com>, Hosein <hosein@example.com>
discussions-to: https://ethereum-magicians.org/t/onchain-ppar
status: Draft
type: Standards Track
category: ERC
requires: 7702, 4337, 4844
created: 2025-06-13
---

## Abstract

This ERC standardises an interface that enables Ethereum accounts to rotate
their signing key by presenting a zero-knowledge proof (ZKP) of knowledge of
one or more private recovery factors (password, e-mail account, or both) while
leaking **no** guardian identities or social-graph metadata on-chain.  The
specification defines a lightweight *Guardian* registry for factor hashes and
a *Verifier* contract that authorises key rotation for EOAs (EIP-7702) and
ERC-4337 smart accounts.


## Motivation

### Key Loss Is Chronic and Costly  
- **Irrecoverable asset loss is endemic.**  
  On-chain forensics estimate **≈20% of all Bitcoin (2.3–3.7 M BTC)** and **≥0.5% of all Ether (≈636k ETH)** are permanently inaccessible due to lost private keys, contract bugs, or forgotten seed phrases.  
  At 2025 market prices, this equates to **tens of billions of USD** in stranded value—capital that can never circulate, invest, or be taxed.

- **Economic side-effects.**  
  A shrinking effective supply introduces unplanned deflationary pressure and complicates monetary modelling. High-profile losses erode user confidence and slow mainstream adoption.

### Existing Recovery Schemes Leak Privacy  
| Approach                      | Drawbacks                                                                                     |
|------------------------------|-----------------------------------------------------------------------------------------------|
| Off-chain seed backups       | Susceptible to physical theft, phishing, and coercion.                                       |
| ERC-4337-style social recovery | Guardian identities and signatures are visible on-chain, exposing social graph data.        |
| Custodial recovery           | Re-introduces trusted intermediaries, undermining self-custody.                              |

### Why a New ERC Is Needed  
1. **On-chain, self-custodial recovery** must preserve privacy while integrating with existing Ethereum account models.  
2. **Zero-knowledge proofs** now allow proving knowledge of recovery secrets without revealing them.  
3. A **standard interface** is required to ensure wallet and verifier interoperability.

---

## Specification

### Terminology and RFC 2119

* **MUST**, **MAY**, **SHOULD**, etc. are per RFC 2119.  
* “Implementer” denotes any contract or circuit author building to this ERC.

### Shared Cryptographic Conventions

| Symbol | Meaning |
|--------|---------|
| `H(⋅)` | Collision-resistant hash function (e.g., keccak256 or Poseidon). |
| `pad(⋅)` | Zero-left-padded 32-byte encoding. |
| `Blob` | EIP-4844 blob containing the zk-proof and auxiliary inputs. |

---

### Storage (Guardian)

```solidity
mapping(address => bytes32) public passwordHash;
mapping(address => bytes32) public emailAddressHash;
mapping(address => uint8)   public recoveryMode; // 0 = none, 1 = password, 2 = emailAddress, 3 = 2FA
```

### Guardian — External Functions

```solidity
function storePassword(address protectedAccount, bytes32 _hash) external;
```

- **MUST** revert unless `msg.sender == protectedAccount`.
- Passing 0x00…00 as the `_hash` deletes the entry.
- **MUST** emit `PasswordStored` on success.

```solidity
function storeEmailAddress(address protectedAccount, bytes32 _hash) external;
function setRecoveryMode(address protectedAccount, uint8 _mode) external;
```

- **MUST** revert unless `msg.sender == protectedAccount`.
- _mode **MUST** be one of 0, 1, 2, 3; otherwise revert.
- Each function **MUST** emit its corresponding event on success.

### Guardian Events

```solidity
event PasswordStored(address indexed protectedAccount, bytes32 hash);
event EmailAddressStored(address indexed protectedAccount, bytes32 hash);
event RecoveryModeSet(address indexed protectedAccount, uint8 mode);
```

### Verifier — External Function

```solidity
function recover(
    bytes32 blobCommitment,  // MAY be 0x0 for calldata-only submissions
    address protectedAccount,
    address newSigner,
    bytes   publicWitnesses, // ABI-encoded, free-form
    bytes   proof            // zk-proof bytes
) external;
```

#### Implementations **MUST**:
1.	Read Guardian.recoveryMode(protectedAccount) and **MUST** reject proofs
inconsistent with that mode.
2.	Decode `publicWitnesses` as specified by the implementer’s circuit.
3.	For every non-zero hash field in `publicWitnesses`, **MUST** assert equality
with the corresponding Guardian storage value.
4.	**MUST** validate proof.
5.	If `blobCommitment == 0x0`, all proof data **MUST** be supplied in
`calldata`; otherwise the contract **MUST** verify that the supplied
commitment matches the blob per EIP-4844 § 4.1.
6.	On success, **MUST** emit `ProofVerified` and invoke `rotateKey`.
7.	**MUST** revert on any failure.

### Internal rotateKey

```solidity
function rotateKey(address protectedAccount, address newSigner) internal;
```

#### Implementations **MUST**:
1.	For EOA `protectedAccount` that adheres to EIP-7702, add the `newSigner` as
the new signer of the `protectedAccount`, with respect to the EIP-7702 specification rules.
2. 	For EIP-4337 `protectedAccount`, add the `newSigner` as the new signer of
the `protectedAccount`, with respect to the EIP-4337 specification rules.
3. 	On success, **MUST** emit `KeyRotated`. 

### Verifier Events

```solidity
event ProofVerified(address indexed protectedAccount);
event KeyRotated(address indexed protectedAccount, address indexed newSigner);
```

### Off-Chain Proof Requirements

| Mode     | Circuit Must Prove                                                               |
|----------|----------------------------------------------------------------------------------|
| Password | `H(pad(password)) == passwordHash`                                               |
| Email Address    | JWT token or DKIM signed token proves email; `H(pad(emaiAddress)) == emailAddressHash`       |
| 2FA      | Both of the above                                                                |

The implementer **MUST** ensure that:
	•	The on-chain hash function equals the one used inside the circuit.
	•	Each authentication factor proven in the circuit corresponds to the chosen
recoveryMode.
	•	Additional fields (expiry, rate-limit flags, etc.) **MAY** be included in
`publicWitnesses` at the implementer’s discretion.

A reference circuit for Gmail DKIM signature proofs is available at <--TODO-->.

## Rationale

•	Minimal Surface – The ERC standardises only what is needed for
interoperability: storage keys, function names, required checks, and event
emissions.
•	Flexibility – Implementers select their preferred hash, proof system,
and witness encoding, provided contract and circuit agree.
•	Privacy – No guardian addresses or signatures appear on chain.


## Security Considerations

•	Implementers **SHOULD** choose a collision-resistant hash (≥ 128-bit).
•	The Verifier’s cross-check between publicWitnesses and Guardian storage
prevents public-input substitution.
•	Replay attacks are mitigated when `newSigner` becomes authorised; proofs are
idempotent thereafter.
•	If blobs are used, data-availability rules of EIP-4844 apply.

## Backwards Compatibility

The ERC is purely application-layer; no consensus changes.  Accounts that
never write to the Guardian contract behave exactly as before.

## Reference Implementation

A reference implementation (Guardian, Verifier contracts, proof circuits including Gmail DKIM signature) is available at:

- <--TODO-->

## Copyright

Copyright and related rights waived via [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
