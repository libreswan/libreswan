/testing/guestbin/swan-prep --x509

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add psk
ipsec add rsa-east
echo "initdone"
