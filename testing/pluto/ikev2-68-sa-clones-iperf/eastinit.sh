/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --status | grep west-east
ipsec whack --impair suppress-retransmits
taskset 0x1 iperf3 -s -p 5002 &
taskset 0x2 iperf3 -s -p 5003 &
taskset 0x3 iperf3 -s -p 5004 &
echo "initdone"
