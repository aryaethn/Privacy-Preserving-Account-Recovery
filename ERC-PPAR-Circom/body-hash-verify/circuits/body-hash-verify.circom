pragma circom 2.0.0;

/*----------------------------------------------------------------------------------------*/
//                                                                                        //
//                                  IMPORTANT NOTE                                        //
//                                                                                        //
/*----------------------------------------------------------------------------------------*/
// This is an exact copy of the header-hash-verify. 
// Since the logic is no different from header-hash-verify, the code is copied completely.

// Include standard library components for hashing, bit manipulation, and comparison.
include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/*
 * @title Bytes2Bits
 * @notice Converts an array of bytes (field elements) into an array of bits (big-endian).
 */
template Bytes2Bits(nBytes) {
    signal input in[nBytes];
    signal output out[nBytes * 8];
    
    component n2b[nBytes];

    for (var i = 0; i < nBytes; i++) {
        n2b[i] = Num2Bits(8);
        n2b[i].in <== in[i];
        for (var j = 0; j < 8; j++) {
            out[i * 8 + j] <== n2b[i].out[7 - j];
        }
    }
}


/*
 * @title Sha256HeaderHasher
 * @notice Proves that the SHA-256 hash of a private `header` matches a public `headerHash`.
 * @param maxHeaderLen The fixed length of the header array. The input must be padded to this size.
 */
// header ([]bytes) : Private
// headerHash (256-bit integer) : Public
template Sha256HeaderHasher(maxHeaderLen) {
    // === INPUTS ===
    // The pre-image, known only to the prover.
    signal input header[maxHeaderLen];
    // The expected hash digest, known by everyone.
    signal input headerHash[2];

    // ---
    // STAGE 1: Convert the header from bytes to bits.
    // ---
    // --- STAGE 5: Hash and Verify ---
    component bytes2bits = Bytes2Bits(maxHeaderLen);
    bytes2bits.in <== header;

    component hasher = Sha256(maxHeaderLen * 8);
    hasher.in <== bytes2bits.out;

    component n2b_high = Num2Bits(128);
    component n2b_low = Num2Bits(128);
    n2b_high.in <== headerHash[0];
    n2b_low.in <== headerHash[1];

    for (var i = 0; i < 128; i++) {
        hasher.out[i] === n2b_high.out[127 - i];
        hasher.out[128 + i] === n2b_low.out[127 - i];
    }
}
