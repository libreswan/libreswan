/testing/guestbin/swan-prep --hostname east
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair allow-null-none
# normally NONE is not emitted
ipsec whack --impair v2-proposal-integ:allow-none
ipsec whack --impair suppress-retransmits
ipsec auto --add west-east
ipsec auto --status | grep west-east
taskset 0x1 iperf3 -s -p 5001 & echo "$!"  > OUTPUT/$(hostname)-iperf3-5001.pid
cd /var/tmp/
# perf record -g -e cycles --call-graph dwarf & echo "$!"  > $(hostname)-perf.pid
# taskset 0x1 iperf3 -s -p 5002 &
# taskset 0x3 iperf3 -s -p 5003 &
echo "initdone"
