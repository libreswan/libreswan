# check traffic status after crashed server restarted
# we expect no tunnel and %pass shunt still in place
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../guestbin/ipsec-kernel-policy.sh
