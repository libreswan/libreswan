# should be empty for east and road
ipsec showstates
# there should be no instance connections
ipsec status | grep "conn serial"
