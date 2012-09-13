: ==== start ====
TESTNAME=ipv6-v6-through-v6-netkey-netkey
source /testing/pluto/bin/westlocal.sh

#FIXME: pings should not need -I
# confirm that the network is alive
ping6 -n -c 4 -I 2001:db8:0:1::254 2001:db8:0:2::254
# make sure that clear text does not get through
# Both these alternatives fail to block the unencrypted icmp ?
## ip6tables -I FORWARD -o eth1 -m policy --dir out --pol ipsec -j ACCEPT
## ip6tables -A FORWARD -o eth1 -m policy --dir out --pol none -p icmp  -j DROP
### ip6tables -t mangle -I PREROUTING -i eth1 -p esp -j MARK --set-mark 50
### ip6tables -t mangle -I INPUT -i eth1 -p esp -j MARK --set-mark 50
### ip6tables -I FORWARD -m mark --mark 50 -j ACCEPT
### ip6tables -A FORWARD -p icmp -j DROP
### ip6tables -I INPUT -m mark --mark 50 -j ACCEPT
### ip6tables -A INPUT -p icmp -j DROP
# confirm with a ping to east-in
ping6 -n -c 4 -I 2001:db8:0:1::254 2001:db8:0:2::254

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-6in6
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt

echo done

