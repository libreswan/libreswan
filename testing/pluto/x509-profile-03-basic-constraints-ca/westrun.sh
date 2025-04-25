# This should fail as the intermediate has no BC=CA; also dump
# intermediate.

./run.sh real/mainca/west-bc-missing-chain-end
ipsec certutil -L -n west-bc-missing-chain-end

# This should fail as the root CA that signed it, and is in EAST's NSS
# DB, has CA=no

./run.sh bc-n-ca/bc-n-ca-west
ipsec certutil -L -n bc-n-ca
