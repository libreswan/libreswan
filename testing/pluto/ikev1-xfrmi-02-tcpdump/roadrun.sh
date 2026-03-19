ipsec auto --up road
# disable ping. tcpdump will be messy, tcpdump is more important here.
# ../../guestbin/ping-once.sh --up 192.1.2.23
../../guestbin/ip.sh -s link show ipsec1
../../guestbin/ip.sh rule show
../../guestbin/ip-route.sh show table 50
../../guestbin/ip-route.sh
echo done
