# restarting ipsec service; OE policies time to load
ipsec restart
../../guestbin/wait-until-pluto-started
../../guestbin/wait-for.sh --match 'loaded 2' -- ipsec status
# should be empty
ipsec showstates
