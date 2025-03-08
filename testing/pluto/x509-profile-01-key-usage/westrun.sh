run() { local l=$1 ; /testing/x509/import.sh real/mainca/$l.all.p12 ; set ipsec certutil -L -n $l ; echo " $@" ; "$@" ; ../../guestbin/ipsec-start-stop.sh $l ; }

run west-ku-missing
run west-ku-digitalSignature
run west-ku-nonRepudiation
run west-ku-certSigning
run west-ku-digitalSignature-certSigning
