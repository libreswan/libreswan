/testing/guestbin/swan-prep --hostname east
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair allow-null-none
ipsec whack --impair no-ikev2-exclude-integ-none,ikev2-include-integ-none
ipsec auto --add west-east
ipsec auto --status | grep west-east
ipsec whack --impair suppress-retransmits
taskset 0x1 iperf3 -s -p 5001 & echo "$!"  > $(hostname)-iperf3-5001.pid
cd /var/tmp/
perf record -g -e cycles --call-graph dwarf & echo "$!"  > $(hostname)-perf.pid
#taskset 0x2 iperf3 -s -p 5002 &
#taskset 0x3 iperf3 -s -p 5003 &
echo "initdone"
