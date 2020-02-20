ipsec auto --up road
# do not send a ping yet. It would confuse the tcpdup
# ping -w 4 -c 4 192.1.2.23
ip -s link show ipsec1
ip rule show
ip route show table 50
ip route
echo done
