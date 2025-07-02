# On-Chain Privacy-Preserving Account Recovery

This repository implements a privacy-preserving account recovery mechanism for Ethereum using zero-knowledge proofs with Circom. The system allows users to securely recover their accounts without exposing sensitive recovery information on-chain.

**NOTE: This README file will be updated as the project progresses.**

## Circuits 💾

### rsa_verify

Can be found in circuits/circom-rsa-verify-main/circuits. 
circom-rsa-verify-main is a direct copy of [ZKP Application/RSA Verify]("https://github.com/zkp-application/circom-rsa-verify").

This circuit is responsible for verifying the RSA Signature of the DKIM signature on the email, and creating a proof of it. 

**Inputs:** 🔌

- exp = 65537 = GooglePubKeyN (nb bigints) : Public
- sign = Signature (nb bigints) : Public
- modulus = GooglePubKeyE (nb bigints) : Public
- hashed = HeaherHash (hashLen bigints) : Public (In case we want consistency, it is better to make the headerHash in this and the Combined circuit be the same)

**Arguments:** 🔧

- w: used in pow_mod.circom. It is needed to be 32
- nb: the number of bits in exp, modulus, and sign
- e_bits: has been set 4, used in pow-mod.circom 
- hashLen: the exact length of hashed


✅ **Have been tested, happy path works correctly!** ✅


### combined

Can be found in circuits/other-circuit.

This circuit is responsible for verifying that the Gmail address is present in the header, and its hash is equal to the gmailHash that is stored in the Gaurdian contract. Also, it checks the hash of the header and the hash of the body.

**Inputs:** 🔌

- header ([]bytes) : Private
- body ([]bytes) : Private
- gmailHash ([2]bigints) : Private (Takes the higher and lower part of the SHA256 hash in two 128-bit integers. This is because the hash field is 256 bits, whereas the ZK field is 254 bits.)
- headerHash ([2]bigints) : Private (Takes the higher and lower part of the SHA256 hash in two 128-bit integers. This is because the hash field is 256 bits, whereas the ZK field is 254 bits.)
- bodyHash ([2]bigints) : Private (Takes the higher and lower part of the SHA256 hash in two 128-bit integers. This is because the hash field is 256 bits, whereas the ZK field is 254 bits.)

**Arguments:** 🔧

- maxSliceLen: The exact length of the header.
- maxOutputLen: The maximum anticipated length of the gmail that is extracted. I think 64 would be ok. 
- maxBodyLen: The exact length of the body.

✅ **Have been tested, happy path works correctly!** ✅

## Notes 🗒️

- The circuits are tested in the Example directory. The tests are on the input files that are extracted by Email-Parser-Go/main.go which uses the Raw-Email.
- To compile and create the proofs, we need the power of tau of 2^20, that can be downloaded [here](https://github.com/iden3/snarkjs?tab=readme-ov-file#7-prepare-phase-2). 



## TO-DO ☑️

After testing the circuits, we need to do the following:

1. Implement a method to do a recursive provin. Probably using [Circom2Gnark](https://github.com/vocdoni/circom2gnark) can be a good idea. But we need correct proofs before doing such thing. ❌
2. Writing smart contracts: Gaurdian, Verifier, and RotateKey. (The Gaurdian and RotateKey are non-ZK, Verifier can be done easily if we use the above method for recursion, using [gnark package](https://docs.gnark.consensys.io/HowTo/prove)). 
3. Writing the ERC in the correct ERC format, and submit it. 
4. Rewriting Email-Parser in JS or TS language (if needed) to be easily used on the browser. 
5. Thinking about the ways that we can make a product out of it. 
