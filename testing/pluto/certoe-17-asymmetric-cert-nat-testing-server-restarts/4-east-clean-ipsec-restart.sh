# confirm tunnel is up
ipsec whack --trafficstatus
# restart ipsec; give OE conns time to load
ipsec restart
../../guestbin/wait-until-pluto-started
# should be empty
ipsec status |grep STATE_
