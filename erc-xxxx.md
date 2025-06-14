---
eip: <to-be-assigned>  
title: On-Chain Privacy-Preserving Account Recovery  
author: Arya, Ardeshir, Hosein
discussions-to: <Ethereum Magicians thread link>  
status: Draft  
type: Standards Track  
category: ERC  
requires: 7702, 2537, 4337, 7864  
created: 2025-06-13  
---

## Table of Contents

- [Abstract](#abstract)  
- [Motivation](#motivation)  
- [Specification](#specification)  
- [Rationale](#rationale)  
- [Security Considerations](#security-considerations)  
- [Backwards Compatibility](#backwards-compatibility)  
- [Reference Implementation](#reference-implementation)  
- [Copyright](#copyright)  
- [References](#references)

---

## Abstract

This ERC standardizes a privacy-preserving, on-chain method for account recovery based on zero-knowledge proofs and optionally two-factor authentication. Unlike traditional social recovery schemes, it enables users to rotate keys using secrets (e.g., passwords or Gmail access) without revealing guardian identities or leaking recovery metadata on-chain. This standard provides an interface for storing recovery parameters, verifying zero-knowledge proofs, and rotating the key of an EOA or smart account in accordance with EIP-7702.

---

## Motivation

### 1. Key Loss Is Chronic and Costly  
- **Irrecoverable asset loss is endemic.**  
  On-chain forensics estimate **≈20% of all Bitcoin (2.3–3.7 M BTC)** and **≥0.5% of all Ether (≈636k ETH)** are permanently inaccessible due to lost private keys, contract bugs, or forgotten seed phrases.  
  At 2025 market prices, this equates to **tens of billions of USD** in stranded value—capital that can never circulate, invest, or be taxed.

- **Economic side-effects.**  
  A shrinking effective supply introduces unplanned deflationary pressure and complicates monetary modelling. High-profile losses erode user confidence and slow mainstream adoption.

### 2. Existing Recovery Schemes Leak Privacy  
| Approach                      | Drawbacks                                                                                     |
|------------------------------|-----------------------------------------------------------------------------------------------|
| Off-chain seed backups       | Susceptible to physical theft, phishing, and coercion.                                       |
| ERC-4337-style social recovery | Guardian identities and signatures are visible on-chain, exposing social graph data.        |
| Custodial recovery           | Re-introduces trusted intermediaries, undermining self-custody.                              |

### 3. Why a New ERC Is Needed  
1. **On-chain, self-custodial recovery** must preserve privacy while integrating with existing Ethereum account models.  
2. **Zero-knowledge proofs** now allow proving knowledge of recovery secrets without revealing them.  
3. **EIP-7702 and EIP-7864** make cost-effective, succinct account modification feasible.  
4. A **standard interface** is required to ensure wallet and verifier interoperability.

### 4. Goals of This ERC  
- **Privacy:** No guardian addresses, signatures, or secrets are exposed.  
- **Interoperability:** Compatible with EOAs, ERC-4337 smart wallets, and EIP-7702.  
- **Auditability:** Stateless verification and canonical public inputs.  
- **Cost Efficiency:** On-chain verification ≤ 1M gas; 1 blob or minimal calldata.  
- **Extensibility:** Supports 2FA, flexible proof schemes, and Gmail-based flows.

---

## Specification

> **Scope and Intent** – This ERC defines interfaces, data structures, and expected behavior for privacy-preserving recovery. It does not prescribe exact implementations, proof systems, or verifier bytecode.

### 1. Shared Cryptographic Conventions

| Symbol | Meaning |
|--------|---------|
| `H(⋅)` | Collision-resistant hash function (e.g., keccak256 or Poseidon). |
| `pad(⋅)` | Zero-left-padded 32-byte encoding. |
| `Blob` | EIP-4844 blob containing the zk-proof and auxiliary inputs. |

---

### 2. Guardian Contract

#### 2.1 Storage

```solidity
mapping(address => bytes32) passwordHash;
mapping(address => bytes32) gmailHash;
mapping(address => uint8) recoveryMode; // 0 = none, 1 = password, 2 = gmail, 3 = 2FA
```

#### 2.2 Methods

```solidity
function storePassword(bytes32 hash) external;
function storeGmail(bytes32 hash) external;
function setRecoveryMode(uint8 mode) external;
```

- msg.sender is always the protected account.
- Overwrites allowed. Passing 0x00…00 deletes entries.

#### 2.3 Events

```solidity
event PasswordStored(address indexed protected, bytes32 hash);
event GmailStored(address indexed protected, bytes32 hash);
event RecoveryModeSet(address indexed protected, uint8 mode);
```

### 3. Verifier Contract

#### 3.1 Method

```solidity
function recover(
    bytes32 blobCommitment,
    address protected,
    address newSigner,
    bytes publicWitnesses
) external;
```

- publicWitnesses contains all public inputs, including passwordHash, gmailHash, protected, newSigner.
- Must match Guardian.recoveryMode.

#### 3.2 Internal Method (abstract)

```solidity
function rotateKey(address protected, address newSigner) internal;
// TODO: Define exact temporary code logic for EIP-7702 deployment
```

#### 3.3 Events

```solidity
event ProofVerified(bytes32 indexed blobCommitment, address indexed protected);
event KeyRotated(address indexed protected, address indexed newSigner);
```

### 4. Off-Chain Proof Requirements

| Mode     | Circuit Must Prove                                                               |
|----------|----------------------------------------------------------------------------------|
| Password | `H(pad(password)) == passwordHash`                                               |
| Gmail    | Google JWT or DKIM signed token proves email; `H(pad(gmail)) == gmailHash`       |
| 2FA      | Both of the above                                                                |

A reference circuit for Gmail JWT and DKIM proofs is available at [GitHub Link].

### 5. Events Summary

| Contract | Event Name         |
|----------|--------------------|
| Guardian | `PasswordStored`   |
| Guardian | `GmailStored`      |
| Guardian | `RecoveryModeSet`  |
| Verifier | `ProofVerified`    |
| Verifier | `KeyRotated`       |

### 6. Gas & Size Guidelines (Informative)

| Operation           | Target Gas   | Notes                            |
|---------------------|--------------|----------------------------------|
| Guardian store      | < 40,000     |                                  |
| Verifier + rotation | ≤ 1,000,000  | Includes full zk-SNARK check     |
| Blob size           | ≤ 128 KB     | 1 blob (EIP-4844)                |

### 7. Non-Goals

- No off-chain key escrow.
- No multi-guardian or threshold logic.
- No required hash function or zk-proof backend.
- No specific bytecode for Verifier or Guardian.

## Rationale

### 1. Separation of Concerns

| Layer  |	Responsibility |	Why This Matters |
|--------|-----------------|-------------------|
| Guardian |	Pure data registry (hashes + mode) |	Keeps state minimal (3 × mapping) and gas-cheap. Updates are idempotent; no proof logic inside. |
| Verifier |	Heavy cryptography + key rotation |	Isolates expensive verification from the lightweight registry, letting alternative proof systems plug in later without touching stored data.|

### 2. Indexing by Protected Address

The mappings use protected (not guardian) as the key so that:
	1.	Self-service UX: The owner (or their wallet UI) can call storePassword/storeGmail directly without first designating a separate guardian contract.
	2.	Privacy: No guardian public key or address ever appears on-chain.
	3.	Gas efficiency: One mapping entry per account avoids N-out-of-M storage footprints.

### 3. Hash-Only Storage

Storing H(pad(secret)) rather than an encrypted secret avoids key-management complexities and leaks no entropy if the registry is hacked. A deterministic padding rule ensures identical pre-images across off-chain and on-chain code.

### 4. Single Guardian, Optional 2-Factor

Early iterations considered threshold (N-of-M) guardians but were rejected for v1:
	•	Adds multi-scalar multiplication to the circuit → higher gas and proof size.
	•	Most real-world “lost key” stories involve a sole holder rather than multi-sig.
The standard explicitly leaves multi-guardian extensions to a future ERC.

### 5. Recovery Mode Flag

Encoding the chosen factor(s) in on-chain state (recoveryMode) lets wallets display the active security posture and allows the Verifier to reject mismatched proofs before expensive pairing checks.

### 6. Choice of EIP Dependencies

•	EIP-7702 – Provides a canonical route to replace an EOA’s signing key without migrating funds or replaying approvals.
•	EIP-2537 (BLS precompiles) – Optional optimisations for BLS-based proof systems (e.g., Plonkish curves).
•	EIP-7864 (Unified Binary Tree) – Makes inclusion proofs cheap if future versions store hashes inside account storage proofs.
•	EIP-4844 – Blob space lowers calldata costs; KZG commitments let the Verifier confirm availability cheaply.

### 7. Proof System Agnosticism

Groth16 is cited only as a benchmark because:
	•	On mainnet today it remains the cheapest verifier (<500 k gas without recursion).
	•	It supports structured-reference string ceremonies that many ZK vendors already run.
However, the ERC words all MUST-level statements in terms of “a zk-proof verifier” so Plonk/KZG or Stark-friendly implementations remain conformant.

### 8. publicWitnesses Vector

A bytes-encoded witness list avoids ABI re-specification each time an implementation tweaks circuit parameters or inserts new rate-limit fields.  It preserves forward compatibility while retaining explicit hashing checks by the Verifier.

### 9. Events for Indexers

Standardised events (PasswordStored, KeyRotated, …) let explorers or custodial dashboards track security-posture changes.  Because no plaintext secret is emitted, on-chain privacy is preserved.

### 10. Gas Targets (Informative Only)

The ≤1 M gas budget was chosen because:
	•	It is ~1% of a post-Dencun 30 M gas block—unlikely to starve block space.
	•	Benchmarks show Groth16 verifiers fit comfortably (<450 k) leaving head-room for rotateKey.
	•	It creates an implicit cap that encourages implementers to optimise circuit size.

### 11. Non-Goals Clarified

•	No off-chain key escrow – custodial recovery solutions already exist.
•	No social-graph disclosure – zero guardian addresses intentionally appear on-chain.
•	No contract upgrade pattern mandated – the standard defines interfaces, not proxy layouts.

### 12. Compatibility & Future Work

The design consciously mirrors ERC-4337 “social recovery” semantics (same intent, different privacy model) so wallet developers can add PPAR with minimal UI changes. Future extensions may include:
	1.	N-of-M guardian thresholds.
	2.	Post-quantum hash and proof curves.
	3.	Additional factors (e.g., hardware attestation) encoded via extra publicWitnesses.


## Security Considerations

### 1. On-Chain Registry Threats

| Risk |	Mitigation |
|--|--|
| Hash-collision or second-preimage attacks against H(⋅) |	Implementations MUST choose a hash with ≥128-bit collision resistance (e.g., keccak256, Poseidon on BN254) and document it.|
| Dictionary attacks on passwordHash or gmailHash (hashes are public) |	Wallet UIs SHOULD enforce minimum entropy (e.g., 12 chars, mixed case) or encourage password managers; padding to 32 bytes eliminates length leakage.|
| Unauthorized registry updates |	Only msg.sender may call storePassword / storeGmail / setRecoveryMode; callers pay gas, discouraging grief attacks on others’ entries.|
| Race/overwrite griefing by malware on the holder’s device |	Users should store secrets off-chain before broadcasting a registry update; overwrites emit events that monitoring tools can flag.|

### 2. Proof Forgery & Verification

| Risk	| Mitigation|
|--|--|
| Forged zk-proof |	Soundness relies on the chosen proof system (e.g., Groth16); implementers MUST verify all pairing equations and check that publicWitnesses exactly match the Guardian hashes.|
| Blob unavailability / DA failure	| The Verifier only needs the commitment; proof bytes are supplied in the same transaction calldata for L1 re-validation or stored in the blob. Validators who do not download the blob will reject the transaction, preventing key rotation without data availability.|
| Public-input substitution	| The contract cross-checks that passwordHash / gmailHash decoded from publicWitnesses equal Guardian storage before verifying, preventing an attacker from constructing a valid proof for the wrong account.|
| Replay of old proofs |	newSigner is part of the public inputs; after a successful rotation it becomes authorised and any second execution with the same newSigner is idempotent. Implementations MAY add an expiry timestamp to publicWitnesses if stronger freshness guarantees are desired.|

### 3. 2-Factor Gmail Path

| Risk |	Mitigation|
|--|--|
| Compromised Google account after rotation |	Recovery can be re-disabled by setting recoveryMode = 0 once access is restored; users should follow standard OPSEC (2FA, hardware keys) on Gmail itself.|
| Cryptographic downgrade (e.g., weak RSA key)	| Circuits MUST verify the JWT’s kid and signature against a pinned modulus list or fetch Google’s JWKS set.|
| Clock skew / token expiry	| Circuits SHOULD include iat/exp checks and enforce a ≤5 min window.|

### 4. Key-Rotation Logic

•	rotateKey is internal and only reachable after proof verification, preventing arbitrary callers from installing a new signer.
•	The exact EIP-7702 flow is marked ⟨TODO⟩; auditors MUST confirm that the deployed temporary code cannot be replayed or self-destructed to roll back the signer set.

### 5. Denial-of-Service & Gas
	
Verifier gas target (≤1 M) leaves head-room in a 30 M block; nevertheless, miners or blob markets could censor recovery txs. Users SHOULD keep secondary recovery avenues (e.g., social recovery) until confirmations settle.

## Backwards Compatibility

1.	No protocol-layer changes: The ERC is a voluntary application-layer standard; nodes, consensus rules, and pre-existing contracts remain unaffected.
2.	EOA & Smart-Wallet Co-existence.
	  •	An account that never opts in to PPAR behaves exactly as before—no Guardian entry, no extra gas costs.
	  •	Wallets may adopt PPAR incrementally; the registry and Verifier interfaces do not conflict with ERC-4337 or multisig recovery schemes.
3.	EIP Dependencies Are Additive.
	  •	EIP-7702 is leveraged only when rotation occurs; non-participating EOAs are untouched.
	  •	Use of EIP-4844 blobs is optional for non-rollup transactions; legacy calldata-only submissions still verify.
4.	Event Topics Preserve Explorer Compatibility: New events (PasswordStored, KeyRotated, etc.) use unique selectors and do not collide with existing widely-used ones, ensuring indexers can integrate without filtering ambiguity.
5.	Forward Compatibility: The publicWitnesses byte array and generic hash function placeholders allow future implementations (e.g., STARKs, post-quantum hashes) without changing function signatures or storage layout.

No known backwards-compatibility risks have been identified.

## Reference Implementation

A reference implementation (Guardian, Verifier contracts, proof circuits including Gmail JWT & DKIM) is available at:

- [https://github.com/your-org/onchain-ppar](https://github.com/your-org/onchain-ppar) <--TODO-->

## Copyright

Copyright and related rights waived via [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).

## References

- [EIP-7702: Temporary Account Contract Code](https://eips.ethereum.org/EIPS/eip-7702)  
- [EIP-2537: BLS12-381 Precompile](https://eips.ethereum.org/EIPS/eip-2537)  
- [EIP-4337: Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)  
- [EIP-7864: Unified Binary Tree](https://eips.ethereum.org/EIPS/eip-7864)  
- [EIP-4844: Shard Blob Transactions](https://eips.ethereum.org/EIPS/eip-4844)
