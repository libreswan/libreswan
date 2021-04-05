# ICMP ping; expect error from trying to delete the kernel's acquire shunt
ipsec whack --oppohere 192.1.2.45 --oppothere 192.1.2.23 --oppoproto 1 --opposport 8 --oppodport 0
../../guestbin/ping-once.sh --up 192.1.2.23
# should show traffic
ipsec whack --trafficstatus
echo done
