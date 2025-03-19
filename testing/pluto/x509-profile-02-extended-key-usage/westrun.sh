# these all work

./eku.sh
./eku.sh ipsecIKE
./eku.sh x509Any

# only those containing ipsecIKE should work
./eku.sh serverAuth
./eku.sh serverAuth-ipsecIKE
./eku.sh serverAuth-critical
./eku.sh clientAuth
./eku.sh clientAuth-ipsecIKE
./eku.sh clientAuth-critical

# only those containing ipsecIKE should work
./eku.sh codeSigning
./eku.sh codeSigning-ipsecIKE
./eku.sh codeSigning-serverAuth
./eku.sh codeSigning-clientAuth
