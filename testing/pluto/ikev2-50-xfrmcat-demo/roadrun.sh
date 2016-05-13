ipsec auto --up road-east
ipsec auto --up road-west
route -n
#iptables -t nat -A POSTROUTING -m policy --dir out --pol ipsec -j SNAT --to-source 10.0.10.1 -d 192.1.2.23
#iptables -t nat -A POSTROUTING -m policy --dir out --pol ipsec -j SNAT --to-source 10.0.10.1 -d 192.1.2.45
ipsec whack --trafficstatus
ping -n -c 2 192.1.2.23
ipsec whack --trafficstatus
ping -n -c 2 192.1.2.45
ipsec whack --trafficstatus
echo done
