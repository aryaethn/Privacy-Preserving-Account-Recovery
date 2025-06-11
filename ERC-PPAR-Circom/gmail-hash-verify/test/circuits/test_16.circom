pragma circom 2.0.0;

// Include your library of templates
include "../../circuits/gmail-hash-verify.circom";

// Instantiate main with a specific configuration for this test
component main {public [gmailHash]} = ExtractAndVerifyHash(16, 32);