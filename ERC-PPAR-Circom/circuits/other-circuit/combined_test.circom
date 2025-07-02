pragma circom 2.0.0;

include "./combined.circom";

component main {public [gmailHash, headerHash, bodyHash]} = CombinedProof(228, 490, 32);