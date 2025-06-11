pragma circom 2.0.0;

// Include your library of templates
include "../../circuits/gmail-hash-verify.circom";

// Instantiate main with a different configuration for this test
component main {public [gmailHash]} = ExtractAndVerifyHash(64, 64);