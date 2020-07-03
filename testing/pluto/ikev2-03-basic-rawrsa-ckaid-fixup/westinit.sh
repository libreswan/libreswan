/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../pluto/bin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
# confirm CKAID is in NSS database
certutil -K -d sql:/etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# will fail due to bug
ipsec auto --add westnet-eastnet-ikev2-ckaid
# load our key via workaround
ipsec auto --add workaround-load-my-pubkey
# will work now :/
ipsec auto --add westnet-eastnet-ikev2-ckaid
echo "initdone"
