ipsec auto --up  westnet-eastnet
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# cause cleartext failure
ip xfrm policy flush
# should cause failures on east
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo done
