ipsec auto --up v6-tunnel
ping6 -n -q -c 4 -I 2001:db8:1:2::45 2001:db8:1:2::23
ipsec _kernel state
ipsec _kernel policy
echo done
