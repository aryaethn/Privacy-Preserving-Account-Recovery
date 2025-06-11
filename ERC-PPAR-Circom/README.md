# On-Chain Privacy-Preserving Account Recovery

This repository implements a privacy-preserving account recovery mechanism for Ethereum using zero-knowledge proofs with Circom. The system allows users to securely recover their accounts without exposing sensitive recovery information on-chain.

**NOTE: This README file will be updated as the project progresses.**

## Circuits 💾

### rsa_verify

Can be found in circom-rsa-verify-main/circuits. 
circom-rsa-verify-main is a direct copy of [ZKP Application/RSA Verify]("https://github.com/zkp-application/circom-rsa-verify").

This circuit is responsible for verifying the RSA Signature of the DKIM signature on the email, and creating a proof of it. 

**Inputs:** 🔌

- exp = 65537 = GooglePubKeyN (nb bits) : Public
- sign = Signature (nb bits) : Private
- modulus = GooglePubKeyE (nb bits) : Public
- hashed = HeaherHash (256 bits) : Public (In case we want consistency, it is better to make this hash look like the one in gmail-hash-verify)

**Arguments:** 🔧

- w: used in pow_mod.circom. It is needed to be 32
- nb: the number of bits in exp, modulus, and sign
- e_bits: has been set 4, used in pow-mod.circom 
- hashLen: the exact length of hashed


✅ **Have been tested, happy path works correctly!** ✅


### gmail-hash-verify

Can be found in gmail-hash-verify/circuits.

This circuit is responsible for verifying that the Gmail address is present in the header, and its hash is equal to the gmailHash that is stored in the Gaurdian contract. 

**Inputs:** 🔌

- header ([]bytes) : Private
- gmailHash ([]integer) : Private (Takes the higher and lower part of the SHA256 hash in two 128-bit integers. This is because the hash field is 256 bits, whereas the ZK field is 254 bits.)

**Arguments:** 🔧

- maxSliceLen: The exact length of the header.
- maxOutputLen: The maximum anticipated length of the gmail that is extracted. I think 64 would be ok. 

✅ **Have been tested, happy path works correctly!** ✅



### header-hash-verify

Can be found in header-hash-verify/circuits.

This circuit is responsible for verifying that the hash of the header of the email is equal to the headerHash which is fed to the previous circuit. 

The equality of this headerHash and the previous circuit's headerHash must be done later. <-- TODO -->

**Inputs:** 🔌

- header ([]bytes) : Private
- headerHash (256-bit integer) : Public

❌ **Not tested. Needs tests** ❌

### body-hash-verify

Can be found in body-hash-verify/circuits.

**NOTE:** This is a full copy from the header-hash-verify. No change!

This circuit is responsible for verifying that the hash of the body of the email is equal to the headerHash.

The equality of body here and the body that is given to the Verifier contract will be checked in the Verifier contract. 

**Inputs:** 🔌

- header ([]bytes) : Private
- headerHash (256-bit integer) : Public

❌ **Not tested. Needs tests** ❌

## Email Parser

Can be found in Email-Parser-Go/main_test.go. 

This code is responsible for parsing the raw email into the correct format of DKIM, and convert the types into the correct type formats for the circuits. 

**NOTE:** This code uses DKIM functions in the go-msgauth library of Go. Since the public functions in the DKIM are not enough for this parsing, we need to have a copy of the full package alongsid our Email-Parser.

✅ **Have been tested, happy path works correctly!** ✅

## TO-DO ☑️

After testing the circuits, we need to do the following:

1. Implement a method to do a recursive provin. Probably using [Circom2Gnark](https://github.com/vocdoni/circom2gnark) can be a good idea. But we need correct proofs before doing such thing. 
2. Writing smart contracts: Gaurdian, Verifier, and RotateKey. (The Gaurdian and RotateKey are non-ZK, Verifier can be done easily if we use the above method for recursion, using [gnark package](https://docs.gnark.consensys.io/HowTo/prove)).
3. Writing the ERC in the correct ERC format, and submit it. 
4. Rewriting Email-Parser in JS or TS language (if needed) to be easily used on the browser. 
5. Thinking about the ways that we can make a product out of it. 
