ipsec auto --up north-dpd
ipsec auto --status | grep northnet-eastnets
ping -n -c 2 -I 192.0.3.254 192.0.2.254
ping -n -c 2 -I 192.0.3.254 192.0.22.254
ipsec whack --trafficstatus
#
ip route add unreachable 192.1.2.23
#sleep 40
sleep 20
sleep 20
ipsec status | grep north-dpd
ip route del unreachable 192.1.2.23
ping -n -c 2 -I 192.0.3.254 192.0.2.254
ping -n -c 2 -I 192.0.3.254 192.0.22.254
# state number shuld be higher than the previous one
ipsec whack --trafficstatus
echo done
