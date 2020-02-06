#check if  tunnel is up
ipsec whack --trafficstatus
# restart ipsec service
ipsec start
# give OE conns time to load
sleep 5
