# confirm tunnel is up
ipsec whack --trafficstatus
# east sends a delete by restarting; # give OE conns time to load
ipsec restart
../../guestbin/wait-until-pluto-started
# should be empty
ipsec showstates
echo waiting on west to re-initiate
