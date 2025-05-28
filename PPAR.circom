pragma circom 2.1.6;
include "poseidon.circom";
include "bn254-schnorr.circom";

template PPAR() {
  // ------------- PUBLIC -----------------
  signal input leafHash;   // Poseidon(secret)
  signal input newPKx;     // new public-key X
  signal input newPKy;     // new public-key Y

  // ------------- PRIVATE ----------------
  signal input secret;     // recovery secret
  signal input sigRx;      // Schnorr R.x
  signal input sigRy;      // Schnorr R.y
  signal input sigS;       // Schnorr s

  // -- Poseidon pre-image constraint -----
  component H = Poseidon(1);
  H.inputs[0] <== secret;
  leafHash === H.out;

  // -- Schnorr signature verification ----
  component V = G1SchnorrVerify();
  V.Rx <== sigRx;
  V.Ry <== sigRy;
  V.S  <== sigS;
  V.pkScalar <== secret;   // pk = secret·G1
  V.msgX <== newPKx;
  V.msgY <== newPKy;
  V.out === 1;             // must be valid
}

component main = PPAR();
