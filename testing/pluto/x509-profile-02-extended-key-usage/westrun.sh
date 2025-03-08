run() { local l=$1 ; /testing/x509/import.sh real/mainca/$l.all.p12 ; set ipsec certutil -L -n $l ; echo " $@" ; "$@" ; ../../guestbin/ipsec-start-stop.sh $l ; }

run west-eku-missing
run west-eku-ipsecIKE
run west-eku-x509Any
run west-eku-serverAuth
run west-eku-clientAuth
run west-eku-codeSigning
run west-eku-ipsecIKE-codeSigning
