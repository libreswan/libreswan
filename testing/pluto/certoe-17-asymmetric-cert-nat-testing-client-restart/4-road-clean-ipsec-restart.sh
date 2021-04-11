# restarting ipsec service; OE policies time to load
ipsec restart
../../guestbin/wait-for.sh --match 'loaded 2' -- ipsec auto --status
# should be empty
ipsec status |grep STATE_
