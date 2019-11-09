/testing/guestbin/swan-prep
# confirm that newtwork is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec _stackmanager start
ipsec pluto --config /etc/ipsec.conf --leak-detective
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ppk
ipsec auto --status | grep westnet-eastnet-ipv4-psk-ppk
ipsec whack --impair suppress-retransmits
echo "initdone"
