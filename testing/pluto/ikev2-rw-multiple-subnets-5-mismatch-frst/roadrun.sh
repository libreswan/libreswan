ipsec auto --up road
# sleep 3
There should be 3 tunnels, and 2 broken tunnels
ipsec trafficstatus
ipsec showstates
echo done
