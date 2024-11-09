ipsec auto --up v6-transport
ping6 -n -q -c 4 -I 2001:db8:1:2::45 2001:db8:1:2::23
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
echo done
