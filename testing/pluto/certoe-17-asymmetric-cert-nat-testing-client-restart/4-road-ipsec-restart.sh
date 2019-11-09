# restart ipsec
ipsec restart
# give OE conns time to load
sleep 5
# should be empty
ipsec status |grep STATE_
