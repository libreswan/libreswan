/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-send-key-size-check all --impair-retransmits
ipsec auto --add westnet-eastnet-aes256
ipsec auto --status | grep westnet-eastnet-aes256
echo "initdone"
