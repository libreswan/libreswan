ping -n -q -c 2 -I 192.1.3.209 192.1.2.23
sleep 5
# should show no tunnels and no bare shunts and a state in STATE_PARENT_I1
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec status |grep STATE_
