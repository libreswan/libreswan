ipsec whack --trafficstatus
ip -s link show ipsec1
ip rule show
../../guestbin/ip.sh route show table 50
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
: ==== cut ====
# this is global will be noisy and change based on host.
../../guestbin/ip.sh address show
: ==== tuc ====
