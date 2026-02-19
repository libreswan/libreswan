/testing/guestbin/swan-prep --userland strongswan
/testing/x509/strongswan-gen.sh
#/testing/x509/openssl-gen.sh

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh strongswan/strong-ED/strongEast.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
ipsec whack --impair suppress-retransmits
echo "initdone"
