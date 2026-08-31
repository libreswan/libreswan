# confirm tunnel is up
ipsec trafficstatus

# restart ipsec; give OE conns time to load
ipsec restart
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 3' -- ipsec status

# should be empty
ipsec showstates
