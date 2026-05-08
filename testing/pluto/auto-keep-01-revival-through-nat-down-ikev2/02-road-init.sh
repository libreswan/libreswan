/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add road-eastnet-ikev2
ipsec whack --impair suppress_retransmits
echo "initdone"
