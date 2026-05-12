# east 01-netbsdeast-add-interface.sh

east# prep.sh

# force the kernel to use fixed IDs

east# sysctl -w net.ipsecif.use_fixed_reqid=1
east# unit=1
east# reqid_ipv4=$(($(sysctl -n net.ipsecif.reqid_base) + 2 * unit))
east# reqid_ipv6=$(($(sysctl -n net.ipsecif.reqid_base) + 2 * unit + 1))

east# ifconfig   ipsec${unit} create
east# ifconfig   ipsec${unit} inet tunnel 192.1.2.23          192.1.2.45
east# ifconfig   ipsec${unit} inet      198.18.23.23/32     198.18.45.45
east# ifconfig   ipsec${unit} inet6  2001:db8:23::23/128 2001:db8:45::45

east# ifconfig ipsec${unit}
east# ipsec _kernel policy

east# route add -inet    198.18.45.0/24    198.18.23.23
east# route add -inet6 2001:db8:45::/64 2001:db8:23::23

# west 02-netbsdwest-add-interface.sh

west# prep.sh

# force the kernel to use fixed IDs

west# sysctl -w net.ipsecif.use_fixed_reqid=1
west# unit=1
west# reqid_ipv4=$(($(sysctl -n net.ipsecif.reqid_base) + 2 * unit))
west# reqid_ipv6=$(($(sysctl -n net.ipsecif.reqid_base) + 2 * unit + 1))

west# ifconfig   ipsec${unit} create
west# ifconfig   ipsec${unit} inet tunnel 192.1.2.45          192.1.2.23
west# ifconfig   ipsec${unit} inet      198.18.45.45/32     198.18.23.23
west# ifconfig   ipsec${unit} inet6  2001:db8:45::45/128 2001:db8:23::23

west# ifconfig ipsec${unit}
west# ipsec _kernel policy

west# route add -inet    198.18.23.0/24    198.18.45.45
west# route add -inet6 2001:db8:23::/64 2001:db8:45::45

# east 03-netbsdeast-add-state.sh

east# echo 'add 192.1.2.45 192.1.2.23 esp 452304 -m transport -u '${reqid_ipv4}' -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
east# echo 'add 192.1.2.23 192.1.2.45 esp 234504 -m transport -u '${reqid_ipv4}' -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c

east# # echo 'add 192.1.2.45 192.1.2.23 esp 452306 -m transport -u '${reqid_ipv6}' -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
east# # echo 'add 192.1.2.23 192.1.2.45 esp 234506 -m transport -u '${reqid_ipv6}' -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c

east# ipsec _kernel state

# west 04-netbsdwest-add-state.sh

west# echo 'add 192.1.2.45 192.1.2.23 esp 452304 -m transport -u '${reqid_ipv4}' -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
west# echo 'add 192.1.2.23 192.1.2.45 esp 234504 -m transport -u '${reqid_ipv4}' -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c

west# # echo 'add 192.1.2.45 192.1.2.23 esp 452306 -m transport -u '${reqid_ipv6}' -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
west# # echo 'add 192.1.2.23 192.1.2.45 esp 234506 -m transport -u '${reqid_ipv6}' -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c

west# ipsec _kernel state

# east 05-netbsdeast-ping.sh

east# ping-once.sh --up    198.18.45.45
east# # ping-once.sh --up 2001:db8:45::45

east# ipsec _kernel state
east# ipsec _kernel policy

# west 06-netbsdwest-ping.sh

west# ping-once.sh --up    198.18.23.23
west# # ping-once.sh --up 2001:db8:23::23

west# ipsec _kernel state
west# ipsec _kernel policy
