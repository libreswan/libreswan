ipsec auto --up eastnet-any
# did we get our IP
../../guestbin/ip.sh address show dev ipsec1
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
# check to see if our resolv.conf got updated
cat /etc/resolv.conf
# confirm resolv.conf is restored on down
ipsec auto --down eastnet-any
cat /etc/resolv.conf
# did we get our IP cleaned up
../../guestbin/ip.sh address show dev ipsec1
echo done
