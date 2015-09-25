ipsec auto --up  west-east
ip addr add 192.1.2.66/24 dev eth1
/sbin/arping -c 1 -U -I eth1 192.1.2.66
ipsec auto --ready
ipsec auto --up float-east
ip addr del 192.1.2.66/24 dev eth1
ipsec auto --ready
ipsec auto --up west-float
# wait for pending cleanups
sleep 30
sleep 30
echo done
