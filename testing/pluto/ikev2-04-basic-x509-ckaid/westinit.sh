/testing/guestbin/swan-prep --x509 --x509name east
eastckaid=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')
/testing/guestbin/swan-prep --x509
westckaid=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')
echo west ckaid: $westckaid east ckaid: $eastckaid
sed -i -e "s/WESTCKAID/$westckaid/" -e "s/EASTCKAID/$eastckaid/" /etc/ipsec.conf
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"
