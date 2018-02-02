/testing/guestbin/swan-prep --46
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -p icmp -j DROP
# confirm with a ping
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-4in6
# alternatively, direct whack
# ipsec whack --name west-east-4in6 --ipv6 --tunnelipv4 --id @west --host 2001:db8:1:2::45 --client 192.0.1.0/24 --to --id @east --host 2001:db8:1:2::23 --client 192.0.2.0/2 --tunnel --psk --encrypt --pfs
echo "initdone"

