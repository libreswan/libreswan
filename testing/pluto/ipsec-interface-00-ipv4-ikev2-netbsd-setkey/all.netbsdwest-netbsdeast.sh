# east 01-netbsdeast-add-interface.sh

east# ../../guestbin/prep.sh
east# 
east# # force the kernel to use fixed IDs
east# 
east# sysctl -w net.ipsecif.use_fixed_reqid=1
east# unit=1
east# reqid_ipv4=$(($(sysctl -n net.ipsecif.reqid_base) + 2 * unit))
east# reqid_ipv6=$(($(sysctl -n net.ipsecif.reqid_base) + 2 * unit + 1))
east# 
east# ifconfig ipsec${unit} create
east# ifconfig ipsec${unit} -link2
east# ifconfig ipsec${unit} inet tunnel 192.1.2.23 192.1.2.45
east# ifconfig ipsec${unit} inet 198.18.23.23/24 198.18.45.45
east# 
east# ifconfig ipsec${unit}
east# ipsec _kernel policy

# west 02-netbsdwest-add-interface.sh

west# ../../guestbin/prep.sh
west# 
west# # force the kernel to use fixed IDs
west# 
west# sysctl -w net.ipsecif.use_fixed_reqid=1
west# unit=1
west# reqid_ipv4=$(($(sysctl -n net.ipsecif.reqid_base) + 2 * unit))
west# reqid_ipv6=$(($(sysctl -n net.ipsecif.reqid_base) + 2 * unit + 1))
west# 
west# ifconfig ipsec${unit} create
west# ifconfig ipsec${unit} -link2
west# ifconfig ipsec${unit} inet tunnel 192.1.2.45 192.1.2.23
west# ifconfig ipsec${unit} inet 198.18.45.45/24 198.18.23.23
west# 
west# ifconfig ipsec${unit}
west# ipsec _kernel policy

# east 03-netbsdeast-add-state.sh

east# echo 'add 192.1.2.45 192.1.2.23 esp 4523 -m transport -u '${reqid_ipv4}'  -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
east# echo 'add 192.1.2.23 192.1.2.45 esp 2345 -m transport -u '${reqid_ipv4}' -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c
east# 
east# ipsec _kernel state

# west 04-netbsdwest-add-state.sh

west# echo 'add 192.1.2.45 192.1.2.23 esp 4523 -m transport -u '${reqid_ipv4}' -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
west# echo 'add 192.1.2.23 192.1.2.45 esp 2345 -m transport -u '${reqid_ipv4}'  -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c
west# 
west# ipsec _kernel state

# east 05-netbsdeast-ping.sh

east# ../../guestbin/ping-once.sh --up -I 198.18.23.23 198.18.45.45
east# 
east# ipsec _kernel state
east# ipsec _kernel policy

# west 06-netbsdwest-ping.sh

west# ../../guestbin/ping-once.sh --up -I 198.18.45.45 198.18.23.23
west# 
west# ipsec _kernel state
west# ipsec _kernel policy

# final final.sh

final# setkey -F
final# ifconfig ipsec1 destroy
final# 
final# 

