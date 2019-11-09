#eck if  tunnel is up
ipsec whack --trafficstatus
# restart ipsec service
systemctl start ipsec
# give OE conns time to load
sleep 5
