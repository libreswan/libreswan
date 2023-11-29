ipsec auto --up road
# disable ping. tcpdump will be messy, tcpdump is more important here.
# ../../guestbin/ping-once.sh --up 192.1.2.23
ip -s link show ipsec1
ip rule show
ip route show table 50
ip route
echo done
