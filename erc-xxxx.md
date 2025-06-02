```
ERC: TBD
Title: Privacy-Preserving Account Recovery with OAuth (PPAR-OAuth)
Authors: Arya, Ardeshir, Hosein
Status: Draft
Type: Standards Track
Category: Wallet
Created: 2025-06-02
Requires: 7702, 2537
```  

## Abstract

This ERC introduces a privacy-preserving account recovery method for EOAs using OAuth credentials (e.g., Google accounts), optionally combined with a password for added security. It leverages EIP-7702 to execute recovery logic in the EOA context and EIP-2537 for efficient BLS12-381 pairing operations during proof verification. All identity checks are wrapped inside a zero-knowledge proof (PLONK + KZG), ensuring that neither the OAuth token nor the user’s password is exposed on-chain.

## Motivation

Current Ethereum wallets are dangerously fragile: loss of the secp256k1 private key results in irrevocable loss of access. While account abstraction (e.g., ERC-4337) and social recovery mechanisms mitigate this risk, they often compromise privacy by exposing secrets or guardian identities on-chain.

PPAR-OAuth preserves the strengths of social recovery while offering:
- Full privacy: no raw secrets or signatures are revealed
- Succinct verification: < 1 MB proof, < 800k gas cost
- Familiar UX: recovery via "Sign in with Google"
- Optional 2FA using password

This is ideal for mass adoption, offering secure recovery with mainstream user flows.

## Specification

### 1. Guardian State

| Item                     | Storage       | Purpose                             |
|--------------------------|---------------|--------------------------------------|
| `emailHash`             | Guardian map  | SHA256(lower(Gmail)) → binds user   |
| `pwHash`, `salt` (opt.) | Guardian map  | Poseidon-hash of password            |
| `mode` (0x01/0x02)      | Guardian map  | Google-only or Google + password     |

### 2. ZK Proofs

#### Mode 0x01: Google only

Statement:
- Know valid ID-token T such that:
  - `ECDSA_P256_Verify(Google_JWKS, T) = true`
  - `SHA256(lower(email in T)) = emailHash`
  - `nonce(T) = N`

Outputs: `(emailHash, newEOA, N)`

#### Mode 0x02: Google + password

Same as above, with:
- `Poseidon(salt ∥ password) = pwHash`

Outputs: `(emailHash, newEOA, N, pwHash, salt)`

#### Proof System
- PLONK + KZG (EIP-2537 precompile support)
- Curve: BLS12-381
- Size: ~1.1 kB
- Gates: ~142,000 (password mode)

### 3. RecoveryFacet (EIP-7702 delegated logic)
```solidity
bytes32 constant PK_X_SLOT = keccak256("ppar.pk.x");
bytes32 constant PK_Y_SLOT = keccak256("ppar.pk.y");

function rotateKey(address newEOA) external {
    assembly {
        sstore(PK_X_SLOT, newEOA)
        sstore(PK_Y_SLOT, 0)
    }
    emit KeyRotated(newEOA);
}
```

### 4. Guardian Contract Logic

```solidity
struct Record {
    address oldEOA;
    bytes32 pwHash;
    bytes32 salt;
    uint8   mode;
}

mapping(bytes32 => Record) public rec;
mapping(bytes32 => bool) public usedN;

IKZGVerifier googleV;   // 3 pub-inputs
IKZGVerifier googlePwV; // 5 pub-inputs

function requestNonce(bytes32 emailH) external returns (bytes32 N) {
    N = keccak256(abi.encodePacked(emailH, blockhash(block.number-1)));
    require(!usedN[N], "inflight");
    emit Nonce(emailH, N);
}

function recover(bytes32 emailH, address newEOA, bytes32 N, bytes calldata proof) external {
    Record memory r = rec[emailH];
    require(r.mode != 0, "unregistered");
    require(!usedN[N],   "nonce used");

    bool ok = (r.mode == 0x01)
        ? googleV.verifyProof(proof, [uint256(emailH), uint256(uint160(newEOA)), uint256(N)])
        : googlePwV.verifyProof(proof, [uint256(emailH), uint256(uint160(newEOA)), uint256(N), uint256(r.pwHash), uint256(r.salt)]);

    require(ok, "bad proof");
    usedN[N] = true;

    bytes memory cd = abi.encodeWithSelector(RecoveryFacet.rotateKey.selector, newEOA);
    _callVia7702(r.oldEOA, cd);

    emit Recovered(r.oldEOA, newEOA, msg.sender, r.mode);
}
```

## Rationale

- **PLONK + KZG on BLS12-381** is chosen for:
  - Universal trusted setup
  - Efficient 1.1 kB proofs for large circuits (~142k gates)
  - Flexibility for future extensions (e.g., WebAuthn)

- **EIP-7702** enables one-time code execution without full smart wallet deployment

- **EIP-2537** pairing precompiles drastically lower verification gas for BLS12-381

- Passwords are optional: mode 0x02 adds minimal cost but maximum resilience

## Backwards Compatibility

Not compatible with pre-7702 environments. Assumes EIP-7702 and EIP-2537 are deployed.

## Security Considerations

- Email hash and nonce prevent token replay
- Guardian does not store plaintext email or secrets
- Signature verified inside circuit via trusted JWKS
- Password hash pre-image check ensures offline second-factor

## Gas Impact

| Component                    | Mode 0x01 | Mode 0x02 |
|-----------------------------|-----------|-----------|
| PLONK verify (pairing + MSM)| 540 k     | 545 k     |
| Storage ops                 | 5 k       | 5 k       |
| `rotateKey` execution       | 240 k     | 240 k     |
| **Total**                   | ~785 k    | ~790 k    |

Cost at 30 gwei / $3k ETH: ~$1.88

## Improvements if EIP-7864 Ships

- Embed `emailHash` into global state tree instead of local mapping
- Benefit: saves ~30k gas on registration and ~5k on recovery
- Cost: add 256-hash Merkle proof (~9k gates) → negligible proof growth

## Flow Diagram

```text
User → Guardian:
 1. requestNonce(emailHash)
 2. receive nonce N
 3. log in with Google (→ ID-token T)
 4a. [optional] enter password
 4b. run prover → ZK proof π
 5. call recover(emailHash, newEOA, N, π)
Guardian:
 6. verify π + check nonce
 7. call rotateKey(oldEOA, newEOA) via 7702
RecoveryFacet:
 8. sstore new key → emit KeyRotated
Guardian:
 9. emit Recovered
```

## Test Cases

- Test valid Google-only recovery
- Test valid Google+password recovery
- Reject reused nonces
- Reject invalid proofs
- Confirm key rotation inside EOA

## Reference Implementation

- Circom circuits for Google JWT + password
- Solidity contracts: `Guardian.sol`, `RecoveryFacet.sol`
- Verifier contracts via `snarkjs` + `zk-verifier-factory`

## Copyright

CC0 Public Domain Dedication

---

PPAR-OAuth upgrades key recovery into a mainstream-compatible flow without exposing sensitive data. Secure, scalable, and developer-friendly, it’s a building block for future identity-anchored wallets.

```
