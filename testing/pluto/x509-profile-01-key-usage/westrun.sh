run() { /testing/x509/import.sh real/mainca/$1.all.p12 ; ../../guestbin/dump-cert-extensions.sh $1 ; ../../guestbin/ipsec-start-stop.sh $1 ; }

run west-ku-missing
run west-ku-digitalSignature
run west-ku-nonRepudiation
run west-ku-certSigning
run west-ku-digitalSignature-certSigning
