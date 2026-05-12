# east 01-freebsdeast-add-interface.sh

east# prep.sh

east# ifconfig ipsec1 create reqid 100
east# ../../guestbin/tcpdump.sh --start -i ipsec1
east# ifconfig ipsec1 inet tunnel 192.1.2.23         192.1.2.45
east# ifconfig ipsec1 inet      198.18.23.23/32    198.18.45.45
east# ifconfig ipsec1 inet6 2001:db8:23::23/128 2001:db8:45::45

east# ifconfig ipsec1
east# ipsec _kernel state
east# ipsec _kernel policy

# west 02-freebsdwest-add-interface.sh

west# prep.sh

west# ifconfig ipsec1 create reqid 100
west# ../../guestbin/tcpdump.sh --start -i ipsec1
west# ifconfig ipsec1 inet tunnel 192.1.2.45         192.1.2.23
west# ifconfig ipsec1 inet      198.18.45.45/32    198.18.23.23
west# ifconfig ipsec1 inet6 2001:db8:45::45/128 2001:db8:23::23

west# ifconfig ipsec1
west# ipsec _kernel state
west# ipsec _kernel policy

# east 03-freebsdeast-add-state.sh

east# echo 'add 192.1.2.45 192.1.2.23 esp 4523 -m tunnel -u 100 -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
east# echo 'add 192.1.2.23 192.1.2.45 esp 2345 -m tunnel -u 100 -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c

east# ifconfig ipsec1
east# ipsec _kernel state
east# ipsec _kernel policy

# west 04-freebsdwest-add-state.sh

west# echo 'add 192.1.2.45 192.1.2.23 esp 4523 -m tunnel -u 100 -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
west# echo 'add 192.1.2.23 192.1.2.45 esp 2345 -m tunnel -u 100 -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c

west# ifconfig ipsec1
west# ipsec _kernel state
west# ipsec _kernel policy

west# sleep 10 # give broken ping a chance

# east 05-freebsdeast-ping.sh

east# ping-once.sh --up    198.18.45.45
east# ping-once.sh --up 2001:db8:45::45

west# sleep 5
east# ../../guestbin/tcpdump.sh --stop -i ipsec1

# west 06-freebsdwest-ping.sh

west# ping-once.sh --up    198.18.23.23
west# ping-once.sh --up 2001:db8:23::23

west# sleep 5
west# ../../guestbin/tcpdump.sh --stop -i ipsec1
