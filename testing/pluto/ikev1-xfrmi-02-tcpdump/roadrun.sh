ipsec auto --up road
# disable ping. tcpdump will be messy, tcpdump is more important here.
# ping -w 4 -c 4 192.1.2.23
ip -s link show ipsec1
ip rule show
ip route show table 50
ip route
echo done
