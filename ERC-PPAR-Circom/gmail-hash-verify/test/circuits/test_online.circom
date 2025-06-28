pragma circom 2.0.0;
include "../../circuits/gmail-hash-verify.circom/";
component main {public [gmailHash]} = ExtractAndVerifyHash(490, 32);
