# these should load properly

ipsec add default-implicit-authby
ipsec add default-specified-authby

ipsec add eddsa
ipsec add eddsa,rsa

ipsec add ecdsa
ipsec add ecdsa,rsa
ipsec add ecdsa-sha2
ipsec add ecdsa-sha2_256
ipsec add ecdsa-sha2_384
ipsec add ecdsa-sha2_512
ipsec add rsa-sha1
ipsec add rsa-sha2
ipsec add rsa-sha2_256
ipsec add rsa-sha2_384
ipsec add rsa-sha2_512

ipsec status |grep policy: | grep -v modecfg

# these should fail to load
cp west-errors.conf /etc/ipsec.d/
echo "include /etc/ipsec.d/west-errors.conf" >> /etc/ipsec.conf
ipsec add ecdsa-sha1-should-fail
ipsec add ikev1-rsa2-should-fail
ipsec add ikev1-ecdsa-should-fail
rm /etc/ipsec.d/west-errors.conf
echo done
