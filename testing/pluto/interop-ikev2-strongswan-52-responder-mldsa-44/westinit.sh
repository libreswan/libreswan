/testing/guestbin/swan-prep --userland strongswan
/testing/x509/strongswan-gen.sh

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh strongswan/strong-MLDSA-44/strongWest.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
