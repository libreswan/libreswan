../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
ipsec stop
# show no nflog left behind
iptables -L -n
