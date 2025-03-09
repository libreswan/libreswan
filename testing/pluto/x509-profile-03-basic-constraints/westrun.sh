run() { local l=$1 ; /testing/x509/import.sh real/mainca/$l.all.p12 ; set ipsec certutil -L -n $l ; echo " $@" ; "$@" ; ../../guestbin/ipsec-start-stop.sh $l ; }

run west-bc-missing
run west-bc-ca-n
run west-bc-ca-n-critical
run west-bc-ca-y-critical
run west-bc-missing-chain-end
# for completeness
ipsec certutil -L -n west-bc-missing-chain-end
