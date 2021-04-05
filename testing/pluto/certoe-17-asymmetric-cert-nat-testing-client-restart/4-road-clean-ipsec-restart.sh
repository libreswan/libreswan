# restarting ipsec service
ipsec restart
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 2' -- ipsec auto --status
# should be empty
ipsec status |grep STATE_
