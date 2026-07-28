/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh strongswan/strong-MLDSA-44/strongWest.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
ipsec whack --impair suppress-retransmits
echo "initdone"
