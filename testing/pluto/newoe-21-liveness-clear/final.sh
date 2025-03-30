hostname | grep nic > /dev/null || ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec _kernel state
ipsec _kernel policy
ipsec _kernel state
ipsec _kernel policy
grep -E "Message ID: [0-9] " /tmp/pluto.log
# grep on east
hostname |grep west > /dev/null || grep -A 1 "has not responded in" /tmp/pluto.log
# A tunnel should have established
grep "^[^|].* established Child SA" /tmp/pluto.log
