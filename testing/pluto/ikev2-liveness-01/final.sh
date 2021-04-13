# should be empty if east triggered
hostname | grep west > /dev/null || ipsec whack --trafficstatus
grep "Message ID: [0-9][0-9]* " /tmp/pluto.log
# grep on east
hostname | grep west > /dev/null || grep -A 1 "has not responded in" /tmp/pluto.log
