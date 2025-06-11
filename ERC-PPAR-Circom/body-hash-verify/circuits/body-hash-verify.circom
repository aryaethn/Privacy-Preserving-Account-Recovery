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
 * @param nBytes The number of bytes in the input array.
 */
template Bytes2Bits(nBytes) {
    signal input in[nBytes];
    signal output out[nBytes * 8];
    
    for (var i = 0; i < nBytes; i++) {
        component n2b = Num2Bits(8);
        n2b.in <== in[i];
        for (var j = 0; j < 8; j++) {
            // Circom's Num2Bits outputs little-endian, so we reverse
            // to get the standard big-endian representation of each byte.
            out[i * 8 + j] <== n2b.out[7 - j];
        }
    }
}


/*
 * @title Sha256HeaderHasher
 * @notice Proves that the SHA-256 hash of a private `header` matches a public `headerHash`.
 * @param maxHeaderLen The fixed length of the header array. The input must be padded to this size.
 */
template Sha256HeaderHasher(maxHeaderLen) {
    // === INPUTS ===
    // The pre-image, known only to the prover.
    signal private input header[maxHeaderLen];
    // The expected hash digest, known by everyone.
    signal public input headerHash[256];

    // ---
    // STAGE 1: Convert the header from bytes to bits.
    // ---
    component bytes2bits = Bytes2Bits(maxHeaderLen);
    for (var i = 0; i < maxHeaderLen; i++) {
        bytes2bits.in[i] <== header[i];
    }

    // ---
    // STAGE 2: Hash the resulting bit array.
    // The Sha256 component's input size must be a constant multiple of 8.
    // ---
    component hasher = Sha256(maxHeaderLen * 8);
    for (var i = 0; i < maxHeaderLen * 8; i++) {
        hasher.in[i] <== bytes2bits.out[i];
    }

    // ---
    // STAGE 3: Constrain the computed hash to equal the public hash.
    // This is the core assertion of the proof. If the hashes do not match,
    // the witness cannot be generated, and the proof will fail.
    // ---
    for (var i = 0; i < 256; i++) {
        headerHash[i] === hasher.out[i];
    }
}

// Example instantiation for a header buffer of 1024 bytes.
component main {public [headerHash]} = Sha256HeaderHasher(1024);