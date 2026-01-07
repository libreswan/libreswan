# check the interface is gone now that road is gone - apparently not?
../../guestbin/ip.sh link show dev ipsec1
# check with connection removed
ipsec auto --delete east
../../guestbin/ip.sh link show dev ipsec1
