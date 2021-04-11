/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n east
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev1
ipsec auto --status | grep westnet-eastnet-ikev1
ipsec whack --impair suppress-retransmits
echo "initdone"
