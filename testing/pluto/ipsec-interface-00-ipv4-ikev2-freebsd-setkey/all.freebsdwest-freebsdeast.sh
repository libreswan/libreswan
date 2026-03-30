# east 01-freebsdeast-add-interface.sh

east# ../../guestbin/prep.sh
east# 
east# ifconfig ipsec1 create reqid 100
east# ifconfig ipsec1 inet tunnel 192.1.2.23 192.1.2.45
east# ifconfig ipsec1 inet 198.18.23.23/24 198.18.45.45
east# 
east# ifconfig ipsec1
east# ipsec _kernel state
east# ipsec _kernel policy

# west 02-freebsdwest-add-interface.sh

west# ../../guestbin/prep.sh
west# 
west# ifconfig ipsec1 create reqid 100
west# ifconfig ipsec1 inet tunnel 192.1.2.45 192.1.2.23
west# ifconfig ipsec1 inet 198.18.45.45/24 198.18.23.23
west# 
west# ifconfig ipsec1
west# ipsec _kernel state
west# ipsec _kernel policy

# east 03-freebsdeast-add-state.sh

east# echo 'add 192.1.2.45 192.1.2.23 esp 4523 -m tunnel -u 100 -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
east# echo 'add 192.1.2.23 192.1.2.45 esp 2345 -m tunnel -u 100 -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c
east# 
east# ifconfig ipsec1
east# ipsec _kernel state
east# ipsec _kernel policy

# west 04-freebsdwest-add-state.sh

west# echo 'add 192.1.2.45 192.1.2.23 esp 4523 -m tunnel -u 100 -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
west# echo 'add 192.1.2.23 192.1.2.45 esp 2345 -m tunnel -u 100 -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c
west# 
west# ifconfig ipsec1
west# ipsec _kernel state
west# ipsec _kernel policy
west# 
west# sleep 10 # give broken ping a chance

# east 05-freebsdeast-ping.sh

east# ../../guestbin/ping-once.sh --up -I 198.18.23.23 198.18.45.45
east# 
east# ipsec _kernel state
east# ipsec _kernel policy

# west 06-freebsdwest-ping.sh

west# ../../guestbin/ping-once.sh --up -I 198.18.45.45 198.18.23.23
west# 
west# ipsec _kernel state
west# ipsec _kernel policy

# final final.sh

final# setkey -F
final# ifconfig ipsec1 destroy
final# 
final# 

