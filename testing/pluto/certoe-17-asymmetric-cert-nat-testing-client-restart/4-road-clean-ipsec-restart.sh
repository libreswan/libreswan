# restarting ipsec service
ipsec restart
# give OE policies time to load
sleep 5
# should be empty
ipsec status |grep STATE_
