/testing/guestbin/swan-prep --x509 --x509name smallkey
certutil -D -n east -d sql:/etc/ipsec.d
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
ipsec whack --impair suppress-retransmits
echo "initdone"
