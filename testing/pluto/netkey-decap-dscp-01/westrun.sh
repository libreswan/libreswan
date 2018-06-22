ipsec auto --up netkey
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ip xfrm state |grep dscp
echo done
