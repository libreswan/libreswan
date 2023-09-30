hostname | grep nic > /dev/null || ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
grep -E "Message ID: [0-9] " /tmp/pluto.log
# grep on east
hostname |grep west > /dev/null || grep -A 1 "has not responded in" /tmp/pluto.log
# A tunnel should have established
grep "^[^|].* established Child SA" /tmp/pluto.log
