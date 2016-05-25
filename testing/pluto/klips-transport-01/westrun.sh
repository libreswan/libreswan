ipsec auto --up  west-east-port3
echo "transmitted text" | nc 192.1.2.23  3
echo "transmitted text" | nc 192.1.2.23  2
ipsec whack --trafficstatus
echo done
