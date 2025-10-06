# these should load properly

ipsec auto --add default-implicit-authby
ipsec auto --add default-specified-authby

ipsec auto --add eddsa
ipsec auto --add eddsa,rsa

ipsec auto --add ecdsa
ipsec auto --add ecdsa,rsa
ipsec auto --add ecdsa-sha2
ipsec auto --add ecdsa-sha2_256
ipsec auto --add ecdsa-sha2_384
ipsec auto --add ecdsa-sha2_512
ipsec auto --add rsa-sha1
ipsec auto --add rsa-sha2
ipsec auto --add rsa-sha2_256
ipsec auto --add rsa-sha2_384
ipsec auto --add rsa-sha2_512

ipsec status |grep policy: | grep -v modecfg

# these should fail to load
cp west-errors.conf /etc/ipsec.d/
echo "include /etc/ipsec.d/west-errors.conf" >> /etc/ipsec.conf
ipsec auto --add ecdsa-sha1-should-fail
ipsec auto --add ikev1-rsa2-should-fail
ipsec auto --add ikev1-ecdsa-should-fail
rm /etc/ipsec.d/west-errors.conf
echo done
