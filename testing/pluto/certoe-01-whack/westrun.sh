ipsec whack --oppohere 192.1.2.45 --oppothere 192.1.2.23
../../guestbin/ping-once.sh --up 192.1.2.23
# should show traffic
ipsec whack --trafficstatus
echo done
