ipsec auto --up rw
# ipsec will configure 100.64.0.x on eth0
../../guestbin/ip.sh address show  dev eth0
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --down rw
#check if the address is removed
../../guestbin/ip.sh address show  dev eth0
echo done
