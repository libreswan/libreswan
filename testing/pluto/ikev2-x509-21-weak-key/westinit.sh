/testing/guestbin/swan-prep --x509 --x509name smallkey
ipsec certutil -D -n east
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
ipsec whack --impair suppress_retransmits
echo "initdone"
