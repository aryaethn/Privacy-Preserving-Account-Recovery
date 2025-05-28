```
ERC: TBD
Title: Privacy-Preserving Account Recovery (PPAR)
Authors: Arya <arya.eth>
Status: Draft
Type: Standards Track
Category: Wallet
Created: 2025-05-27
Requires: 7864, 7702, 4844
```  

## Abstract

This ERC defines a standard for privacy-preserving account recovery (PPAR) for Ethereum EOAs. PPAR leverages the Unified Binary Tree state model from EIP-7864, temporary contract execution from EIP-7702, and efficient calldata handling from EIP-4844 to enable secure key rotation by guardians using SNARKs. It ensures guardians do not expose secrets or raw signatures while remaining cost-effective and forward-compatible with evolving proof systems.

## Motivation

Social recovery is critical for onboarding and long-term self-custody but often exposes private recovery secrets or relies on smart contracts with upgrade risks. PPAR enables:

- Guardians to authenticate via zero-knowledge proof of knowledge of a secret.
- Account owners to recover control without revealing private data or deploying permanent contracts.
- Minimal on-chain footprint using existing standards.

| Enabling EIP | What it changes | Why PPAR needs it |
|-------------|------------------|--------------------|
| EIP-7864 | Replaces hexary Patricia trie with balanced binary Merkle tree | Guardians can store `Poseidon(secret)` directly as a leaf |
| EIP-7702 | EOAs can execute one-off code per transaction | Allows recovery logic to be executed from the EOA context |
| EIP-4844 | Introduces blobs for efficient calldata | SNARK proofs and Merkle paths fit in a single blob |

## Specification

### 1. Protocol Overview

Statement: Prove knowledge of `secret` such that:
- `Poseidon(secret) == leafHash`
- `Schnorr(secret, newPK) == valid`

Public Inputs:
- `leafHash`, `newPKx`, `newPKy`

Proof System:
- Baseline: Groth16 on BN254

### 2. On-chain Execution

Recovery is triggered via an EIP-7702 transaction containing `RecoveryFacet` logic. On-chain steps:

1. Resolve state root (blockhash or relay)
2. Verify Merkle inclusion of leafHash
3. Confirm SNARK proof validity
4. Confirm new public key is on-curve
5. Write new key to EOA storage slots

### 3. Circuit Definition

- Poseidon pre-image: ~250 constraints
- Schnorr signature: ~7,200 constraints
- Glue logic: ~150 constraints
- Total: ~7,600 constraints

Verifier: Solidity verifier exported from `snarkjs`

### 4. Shared Contracts

**StateRootRelay**
- Caches state roots for >256-block-old recoveries

**RecoveryFacet**
- Performs Merkle verification, SNARK verification, and key rotation
- Emits `KeyRotated(account, guardian, pkX, pkY)`

### 5. Calldata & Gas

- Calldata size: ~8.5 kB (fits one EIP-4844 blob)

| Path Type        | Verify Gas | Extra Gas         | Total |
|------------------|------------|-------------------|-------|
| Direct (<256 blk)| ~228k      | ~12k              | ~240k |
| Relay-root       | ~228k      | ~32k (relay+extra)| ~260k |

### 6. Formal Semantics

Two sstore operations to persistent slots inside the EOA:
```solidity
sstore(PK_X_SLOT, newX);
sstore(PK_Y_SLOT, newY);
```

Wallets validate future signatures using these slots—no registry or proxy needed.

### 7. Guardian CLI

```sh
ppar witness secret newX newY path idx root headerNum > witness.json
snarkjs groth16 prove ppar.zkey witness.json proof.json
ppar send --account guardian.eth proof.json --new-key newX:newY --path ... --idx ... --header headerNum
```

## Rationale

- **BN254 + Groth16**: Optimal for cost-efficiency and precompile availability
- **Poseidon hash**: Chosen for SNARK-native efficiency
- **Schnorr signature**: Enables `secret` to serve as both proof and signer key
- **EIP-7702**: Enables execution from EOAs without contract deployment
- **EIP-4844**: Ensures calldata (SNARK, path, metadata) fits within a single blob

## Backwards Compatibility

Not backward compatible with pre-7864 state model. Requires EIP-7864, EIP-7702, and EIP-4844 to be activated on the network.

## Security Considerations

- SNARK Soundness: Relies on Groth16, Poseidon, Schnorr, and DLP assumptions
- Replay Protection: `newPK` is signed and cross-verified
- Root Validity: Blockhash or relay-provided root
- Circuit Safety: Public input check and curve validation block invalid proofs

## Test Cases

Unit tests must verify:
- Successful key rotation with valid SNARK & path
- Invalid path rejections
- Invalid proof rejections
- Invalid public key rejections
- Relay-root handling

## Reference Implementation

- Circom circuit: `ppar.circom`
- Solidity contracts: `RecoveryFacet.sol`, `StateRootRelay.sol`, `Verifier.sol`
- CLI tool: `ppar.js`

## Copyright

Copyright and related rights waived via CC0.

---

This ERC defines a modular, zk-powered recovery mechanism usable in modern Ethereum post-7864. It balances privacy, simplicity, gas-efficiency, and extensibility, and should serve as the base for future enhancements like threshold recovery, post-quantum zk-schemes, and zk-bridging.

```
