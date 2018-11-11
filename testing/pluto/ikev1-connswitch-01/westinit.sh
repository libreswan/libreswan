/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n east
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev1
ipsec auto --status | grep westnet-eastnet-ikev1
ipsec whack --impair suppress-retransmits
echo "initdone"
