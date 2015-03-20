ipsec auto --up ipip-sourceroute
ping -n -c 4 192.1.2.23
ping -n -c 4 1.1.1.3
route -n
ifdown eth1
ifup eth1
route -n
ping -n -c 4 192.1.2.23
ping -n -c 4 1.1.1.3
echo done
