# one packet, which gets eaten by XFRM, so east does not initiate
ping -n -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE IKE negotiation
sleep 1
ping -n -c 2 -I 192.1.3.209 192.1.2.23
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../pluto/bin/ipsec-look.sh
iptables -t nat -L -n
ipsec stop
conntrack -L -n | sed -e "s/id=[0-9]*/id=XXXX/g" -e "s/icmp     1 [0-9]*/icmp     1 XX/" | sort
conntrack -F
iptables -t nat -L 
iptables -t nat -F 
ipsec start
# packet trigger OE
ping -n -c 1 -I 192.1.3.209 192.1.2.23
sleep 1
ping -n -c 2 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../pluto/bin/ipsec-look.sh
iptables -t nat -L -n
conntrack -L -n | sed -e "s/id=[0-9]*/id=XXXX/g" -e "s/icmp     1 [0-9]*/icmp     1 XX/" | sort
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
# ping should succeed through tunnel
echo done
