# Privacy Preserving Account Recovery (PPAR)

This repository had been created to form as an ERC within the Ethereum improvement proposals. The name is pretty self explanatory: How to recover a missing-key account in a private manner in the Ethereum ecosystem. 

Unfortunately, we, [@4rdii](https://github.com/4rdii) and I, have been delayed by our "perfectionism," and lost the race to two other incredible ERCs: 

1. ERC-7947: [Account Abstraction Recovery Interface (AARI)](https://github.com/ethereum/ERCs/blob/master/ERCS/erc-7947.md) by Artem Chystiakov ([@arvolear](https://github.com/Arvolear))
2. ERC-7969: [DKIM Registry for DKIM Verification](https://github.com/ethereum/ERCs/pull/1084) by Mike Fu (@fumeng00mike) et al.

Noting our work was going to be a combination of these two ERCs, we respected them by not publishing our work as a separate ERC. 

The structure is as below:
1. Email Parser: A code in Go programming language, based on DKIM registry to parse a raw email in DKIM format to extract the signatures.
2. Circuits: Zero-knowledge circuits in Circom programming language, to provide the needed proofs for a DKIM signature ZKP to be given to a Verifier contract on-chain.

