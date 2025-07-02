# Install NebraZKP/UPA
sudo npm install -g @nebrazkp/upa


# Convert Verification Keys into the UPA Format
upa convert vk-snarkjs  --snarkjs-vk rsa_verification_key.json     \
                        --vk-file   rsa_vk.upa.json
upa convert vk-snarkjs  --snarkjs-vk combined_verification_key.json   \
                        --vk-file   combined_vk.upa.json


# Create UPA-understandable proofs from Proofs and Publics
jq -s '{ proof: .[0], publicSignals: .[1] }'  \
        rsa_proof.json   rsa_public.json    > rsa_snarkjs.json
jq -s '{ proof: .[0], publicSignals: .[1] }'  \
        combined_proof.json combined_public.json  > combined_snarkjs.json



# Convert Proofs into the UPA Format
upa convert proof-snarkjs \                    
      --snarkjs-proof rsa_snarkjs.json   \
      --proof-file    rsa.upa.json

upa convert proof-snarkjs \
      --snarkjs-proof combined_snarkjs.json \
      --proof-file    combined.upa.json




