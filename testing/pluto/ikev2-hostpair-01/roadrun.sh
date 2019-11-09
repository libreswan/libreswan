ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
ping -n -c 2 -I 192.0.2.1 192.1.2.23
ipsec whack --trafficstatus
# change ip, emulating switching network
killall -9 pluto
ifconfig eth0 192.1.3.210 netmask 255.255.255.0
route add default gw 192.1.3.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
# should not fail to ping
ping -n -c 4 -I 192.0.2.1 192.1.2.23
ipsec whack --trafficstatus
echo done
