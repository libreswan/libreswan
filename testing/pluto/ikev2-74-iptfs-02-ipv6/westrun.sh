ipsec auto --up v6-tunnel
ping6 -n -q -c 4 2001:db8:1:2::23
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
echo done
