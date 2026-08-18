# use strongswan config to generate keys in OUTPUT/strongswan
/testing/guestbin/swan-prep --userland strongswan
/testing/x509/bin/strongswan.sh strong-ED --type ed25519

# now config for pluto; importing key
/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh $PWD/OUTPUT/strongswan/strong-ED/strongEast.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
ipsec whack --impair suppress-retransmits
echo "initdone"
