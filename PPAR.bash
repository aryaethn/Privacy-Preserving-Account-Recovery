circom ppar_google_pw.circom --r1cs --wasm -o build
# universal CRS assumed (PLONK on BLS12-381)
snarkjs plonk setup build/ppar_google_pw.r1cs powersOfTau28_hez_final_20.ptau ppar_pw.zkey
snarkjs zkey export solidityverifier ppar_pw.zkey VerifierGooglePw.sol
