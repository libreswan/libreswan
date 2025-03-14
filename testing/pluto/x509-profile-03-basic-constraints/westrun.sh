run() { local c=$(basename $1) ; /testing/x509/import.sh real/$1.all.p12 ; set ipsec certutil -L -n $c ; echo " $@" ; "$@" ; ../../guestbin/ipsec-start-stop.sh $c ; }

# playing with end cert Basic Constraint should have no effect, these
# all establish

run mainca/west-bc-missing
run mainca/west-bc-ca-n
run mainca/west-bc-ca-n-critical
run mainca/west-bc-ca-y
run mainca/west-bc-ca-y-critical

# this should fail as the intermediate has no BC=CA; also dump
# intermediate

run mainca/west-bc-missing-chain-end
ipsec certutil -L -n west-bc-missing-chain-end

# this should fail as the root CA that signed it, and is in EAST's NSS
# DB, has CA=no
run bc-n-ca/bc-n-ca-west
ipsec certutil -L -n bc-n-ca
