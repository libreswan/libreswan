# confirm tunnel is up
ipsec whack --trafficstatus
# east sends a delete by restarting
ipsec restart
# give OE conns time to load
sleep 5
# should be empty
ipsec status |grep STATE_
echo waiting on west to re-initiate
