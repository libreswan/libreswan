ipsec auto --up  westnet-all
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ip route list
# testing re-orienting
ipsec auto --replace westnet-all
ipsec auto --status |grep westnet
echo done
