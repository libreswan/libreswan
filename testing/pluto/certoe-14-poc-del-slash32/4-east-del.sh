# confirm tunnel is up
ipsec whack --trafficstatus
# east sends a delete by restarting; give OE conns time to load
ipsec restart
../../guestbin/wait-until-pluto-started
# should be empty
ipsec status |grep STATE_
echo waiting on road to re-initiate
