# check the interface is gone now that road is gone - apparently not?
ip link show dev ipsec1
# check with connection removed
ipsec auto --delete east
ip link show dev ipsec1
