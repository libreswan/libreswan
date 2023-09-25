ipsec auto --up ikev2-west-east
ping -n -q -c 4 192.1.2.23
ipsec whack --trafficstatus
# should show tcp being used
../../guestbin/ipsec-look.sh 2>/dev/null | grep encap
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
ipsec auto --down ikev2-west-east
echo "done"
