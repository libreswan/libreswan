# should be empty for east and road
ipsec status |grep STATE_
# there should be no instance connections
ipsec status | grep "conn serial"
