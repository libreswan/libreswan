/testing/guestbin/swan-prep --x509 --x509name west-nosan
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
ipsec status | grep idtype
ipsec whack --impair suppress_retransmits
echo "initdone"
