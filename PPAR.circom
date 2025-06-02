/*───────────────────────────────────────────────────────────────────────*\
 |  Google + Password Recovery – Circom 2.1.x                           |
\*───────────────────────────────────────────────────────────────────────*/

pragma circom 2.1.6;

include "sha256.circom";       // ↳ sha256Bytes()
include "ecdsa_p256.circom";   // ↳ EcdsaP256Verify()
include "poseidon.circom";     // ↳ Poseidon(2)

/* -------------------------------------------------------------------- */
/*  Substitute these constants with a real Google ES256 public key      */
template GooglePubKey() {
    signal output x;
    signal output y;
    // 256-bit X,Y affine coordinates on P-256
    x <-- 0xd458e7d127ae671b0c330266d246769353a012073e97acf83e0c204886d55b32;
    y <-- 0x325c8dc72966d469308b66f32b3b4d1030c16f0d4e38ff2ff7bc3e5d1e7e2d90;
}

/* 256-bit equality helper */
template AssertEq256() { signal input a; signal input b; a === b; }

/* -------------------------------------------------------------------- */
/*  Two-factor circuit                                                  */
template GoogleWithPassword() {
    /* -------- PUBLIC -------- */
    signal input emailHash;   // SHA-256(lower(email))
    signal input newEOA;      // uint160 in Fr
    signal input nonce;       // guardian nonce
    signal input pwHash;      // Poseidon(salt||pw)
    signal input salt;        // 32-byte salt

    /* -------- PRIVATE ------- */
    signal input msgHash;          // SHA-256(header||payload)
    signal input sigR;
    signal input sigS;
    signal input emailBytes[64];   // lowercase email (≤64B, 0-padded)
    signal input tokenNonce;       // nonce field inside JWT
    signal input password;         // user password (≤31B)

    /* 1️⃣  Google signature check */
    component K  = GooglePubKey();
    component V  = EcdsaP256Verify();
    V.publicKeyX <== K.x;
    V.publicKeyY <== K.y;
    V.msgHash    <== msgHash;
    V.sigR       <== sigR;
    V.sigS       <== sigS;
    V.out === 1;

    /* 2️⃣  Email hash */
    component Hmail = Sha256Bytes(64);
    for (var i = 0; i < 64; i++)  Hmail.in[i] <== emailBytes[i];
    Hmail.out === emailHash;

    /* 3️⃣  Nonce equality */
    tokenNonce === nonce;

    /* 4️⃣  Password hash */
    component Hpw = Poseidon(2);
    Hpw.inputs[0] <== salt;
    Hpw.inputs[1] <== password;
    Hpw.out === pwHash;
}

/* Top-level */
component main = GoogleWithPassword();
