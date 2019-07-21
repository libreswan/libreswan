# check traffic status after crashing server
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ping should succeed through tunnel
ping -n -c 5 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
