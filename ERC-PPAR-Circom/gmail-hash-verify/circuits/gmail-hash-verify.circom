pragma circom 2.0.0;

// Standard library components for hashing and comparison.
include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/*
 * @title SubArrayEquals
 * @notice Compares a prefix of `slice` with `sub` up to a given `len`.
 */
template SubArrayEquals(maxLen) {
    var nBits = 16;
    signal input slice[maxLen];
    signal input sub[maxLen];
    signal input len; // The actual length to compare
    signal output out;

    component i_lt_len[maxLen];
    component eq[maxLen];
    signal isMatch[maxLen];
    signal runningProduct[maxLen];

    for (var i = 0; i < maxLen; i++) {
        i_lt_len[i] = LessThan(nBits);
        i_lt_len[i].in[0] <== i;
        i_lt_len[i].in[1] <== len;

        eq[i] = IsEqual();
        eq[i].in[0] <== slice[i];
        eq[i].in[1] <== sub[i];
        
        // isMatch is 1 if (i >= len) or (slice[i] == sub[i])
        isMatch[i] <== (1 - i_lt_len[i].out) + i_lt_len[i].out * eq[i].out;
    }
    
    // Accumulate the product across a signal array
    runningProduct[0] <== isMatch[0];
    for (var i = 1; i < maxLen; i++) {
        runningProduct[i] <== runningProduct[i - 1] * isMatch[i];
    }

    // The output is the final accumulated product
    out <== runningProduct[maxLen - 1];
}

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
 * @title ExtractAndVerifyHash
 * @notice Extracts a substring from a header and verifies its SHA-256 hash.
 * @dev The item "from:" is hardcoded. The extracted string is padded to maxOutputLen before hashing.
 */
template ExtractAndVerifyHash(maxSliceLen, maxOutputLen) {
    // === INPUTS ===
    signal input header[maxSliceLen];
    signal input gmailHash[2];

    // === CONSTANTS ===
    var nBits = 16;
    signal ltChar <== 60; // '<'
    signal gtChar <== 62; // '>'

    var item[5];
    var itemLen = 5;
    item[0] = 102; item[1] = 114; item[2] = 111; item[3] = 109; item[4] = 58;

    // --- STAGE 1: Find "from:" ---
    component isSubarray[maxSliceLen];
    for (var i = 0; i < maxSliceLen; i++) {
        isSubarray[i] = SubArrayEquals(5);
        isSubarray[i].len <== itemLen;
        for (var j = 0; j < 5; j++) {
            isSubarray[i].slice[j] <== (i + j < maxSliceLen) ? header[i + j] : 0;
            isSubarray[i].sub[j] <== item[j];
        }
    }
    signal firstMatchFlag[maxSliceLen];
    signal matchFoundSoFar[maxSliceLen + 1];
    matchFoundSoFar[0] <== 0;
    for (var i = 0; i < maxSliceLen; i++) {
        firstMatchFlag[i] <== isSubarray[i].out * (1 - matchFoundSoFar[i]);
        matchFoundSoFar[i+1] <== matchFoundSoFar[i] + firstMatchFlag[i];
    }
    signal itemFound <== matchFoundSoFar[maxSliceLen];
    signal itemIndexAccumulator[maxSliceLen + 1];
    itemIndexAccumulator[0] <== 0;
    for (var i = 0; i < maxSliceLen; i++) {
        itemIndexAccumulator[i+1] <== itemIndexAccumulator[i] + i * firstMatchFlag[i];
    }
    signal itemIndex <== itemIndexAccumulator[maxSliceLen];
    signal searchStart <== itemIndex + itemLen;

    // --- STAGE 2: Find '<' ---
    component isLtChar[maxSliceLen];
    component isAfterItem[maxSliceLen];
    signal firstLtFlag[maxSliceLen];
    signal ltFoundSoFar[maxSliceLen + 1];
    signal firstflaghelper[maxSliceLen];
    signal firstflaghelper2[maxSliceLen];
    ltFoundSoFar[0] <== 0;
    for (var i = 0; i < maxSliceLen; i++) {
        isLtChar[i] = IsEqual(); isLtChar[i].in[0] <== header[i]; isLtChar[i].in[1] <== ltChar;
        isAfterItem[i] = LessThan(nBits); isAfterItem[i].in[0] <== searchStart - 1; isAfterItem[i].in[1] <== i;
        firstflaghelper[i] <== isLtChar[i].out * itemFound;
        firstflaghelper2[i] <== firstflaghelper[i] * isAfterItem[i].out;
        firstLtFlag[i] <== firstflaghelper2[i] * (1 - ltFoundSoFar[i]);
        ltFoundSoFar[i+1] <== ltFoundSoFar[i] + firstLtFlag[i];
    }
    signal ltIndexAccumulator[maxSliceLen + 1];
    ltIndexAccumulator[0] <== 0;
    for (var i = 0; i < maxSliceLen; i++) { ltIndexAccumulator[i+1] <== ltIndexAccumulator[i] + i * firstLtFlag[i]; }
    signal ltIndex <== ltIndexAccumulator[maxSliceLen];
    signal fromIndex <== ltIndex + 1;


    // --- STAGE 3: Find '>' ---
    signal ltFound <== ltFoundSoFar[maxSliceLen];
    component isGtChar[maxSliceLen];
    component isAfterLt[maxSliceLen];
    signal firstGtFlag[maxSliceLen];
    signal gtFoundSoFar[maxSliceLen + 1];
    signal firstflaghelper3[maxSliceLen];
    signal firstflaghelper4[maxSliceLen];
    gtFoundSoFar[0] <== 0;
    for (var i = 0; i < maxSliceLen; i++) {
        isGtChar[i] = IsEqual(); isGtChar[i].in[0] <== header[i]; isGtChar[i].in[1] <== gtChar;
        isAfterLt[i] = LessThan(nBits); isAfterLt[i].in[0] <== ltIndex; isAfterLt[i].in[1] <== i + 1;
        firstflaghelper3[i] <== isGtChar[i].out * ltFound;
        firstflaghelper4[i] <== firstflaghelper3[i] * isAfterLt[i].out;
        firstGtFlag[i] <== firstflaghelper4[i] * (1 - gtFoundSoFar[i]);
        gtFoundSoFar[i+1] <== gtFoundSoFar[i] + firstGtFlag[i];
    }
    signal toIndexAccumulator[maxSliceLen + 1];
    toIndexAccumulator[0] <== 0;
    for (var i = 0; i < maxSliceLen; i++) { toIndexAccumulator[i+1] <== toIndexAccumulator[i] + i * firstGtFlag[i]; }
    signal toIndex <== toIndexAccumulator[maxSliceLen];


    // --- STAGE 4: Extract substring ---
    signal gtFound <== gtFoundSoFar[maxSliceLen];
    signal allFoundHelper <== itemFound * ltFound;
    signal allFound <== allFoundHelper * gtFound;
    component toIsGtFrom = LessThan(nBits); toIsGtFrom.in[0] <== fromIndex; toIsGtFrom.in[1] <== toIndex;
    signal validIndices <== toIsGtFrom.out;
    signal potentialLen <== toIndex - fromIndex;
    signal actualLenHelper <== allFound * validIndices;
    signal actualLen <== actualLenHelper * potentialLen;
    component lenIsLeMax = LessThan(nBits); lenIsLeMax.in[0] <== actualLen; lenIsLeMax.in[1] <== maxOutputLen + 1;
    signal outLen <== actualLen * lenIsLeMax.out;

    signal extracted[maxOutputLen];
    component iIsLtOutLen[maxOutputLen];
    signal srcIndex[maxOutputLen];
    component isJEqSrc[maxOutputLen][maxSliceLen];
    signal charToSelectAccumulator[maxOutputLen][maxSliceLen + 1];
    for (var i = 0; i < maxOutputLen; i++) {
        iIsLtOutLen[i] = LessThan(nBits); iIsLtOutLen[i].in[0] <== i; iIsLtOutLen[i].in[1] <== outLen;
        srcIndex[i] <== fromIndex + i;
        charToSelectAccumulator[i][0] <== 0;
        for (var j = 0; j < maxSliceLen; j++) {
            isJEqSrc[i][j] = IsEqual(); isJEqSrc[i][j].in[0] <== srcIndex[i]; isJEqSrc[i][j].in[1] <== j;
            charToSelectAccumulator[i][j+1] <== charToSelectAccumulator[i][j] + isJEqSrc[i][j].out * header[j];
        }
        extracted[i] <== iIsLtOutLen[i].out * charToSelectAccumulator[i][maxSliceLen];
    }

    // --- STAGE 5: Hash and Verify ---
    component bytes2bits = Bytes2Bits(maxOutputLen);
    bytes2bits.in <== extracted;

    component hasher = Sha256(maxOutputLen * 8);
    hasher.in <== bytes2bits.out;

    component n2b_high = Num2Bits(128);
    component n2b_low = Num2Bits(128);
    n2b_high.in <== gmailHash[0];
    n2b_low.in <== gmailHash[1];

    for (var i = 0; i < 128; i++) {
        hasher.out[i] === n2b_high.out[127 - i];
        hasher.out[128 + i] === n2b_low.out[127 - i];
    }
}
