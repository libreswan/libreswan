ipsec auto --up test1
../../guestbin/ping-once.sh --up -I 192.1.3.2 192.1.3.1
ipsec whack --trafficstatus
../../guestbin/ip.sh address add 192.1.3.3/24 dev eth3
ipsec auto --ready
ipsec auto --status |grep "[.][.][.]"
ipsec auto --up test2
../../guestbin/ping-once.sh --up -I 192.1.3.3 192.1.3.1
ipsec whack --trafficstatus
../../guestbin/ip.sh address del 192.1.3.3/24 dev eth3
ipsec auto --ready
ipsec auto --status |grep "[.][.][.]"
