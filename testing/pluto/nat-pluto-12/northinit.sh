/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nat
ipsec whack --impair suppress-retransmits
echo "initdone"
