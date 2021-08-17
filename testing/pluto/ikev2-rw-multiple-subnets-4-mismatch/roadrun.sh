ipsec auto --up road
sleep 3
# There should be 6 tunnels up, and 2 broken tunnels
ipsec trafficstatus
ipsec showstates
echo done
