run() { local c=$(basename $1) ; /testing/x509/import.sh $1.p12 ; set ipsec certutil -L -n $c ; echo " $@" ; "$@" ; ../../guestbin/ipsec-start-stop.sh $c ; }

# This should fail as the intermediate has no BC=CA; also dump
# intermediate.

run real/mainca/west-bc-missing-chain-end
ipsec certutil -L -n west-bc-missing-chain-end

# This should fail as the root CA that signed it, and is in EAST's NSS
# DB, has CA=no

run bc-n-ca/bc-n-ca-west
ipsec certutil -L -n bc-n-ca
