run() { /testing/x509/import.sh real/mainca/$1.all.p12 ; ../../guestbin/dump-cert-extensions.sh $1 ; ../../guestbin/ipsec-start-stop.sh $1 ; }

run west-eku-missing
run west-eku-ipsecIKE
run west-eku-x509Any
run west-eku-serverAuth
run west-eku-clientAuth
run west-eku-codeSigning
run west-eku-ipsecIKE-codeSigning
