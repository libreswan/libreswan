../../guestbin/prep.sh

ifconfig ipsec1 create
ifconfig ipsec1 -link2
ifconfig ipsec1 inet tunnel 192.1.2.45 192.1.2.23
ifconfig ipsec1 inet 192.0.45.1/24 192.0.23.1

ifconfig ipsec1
../../guestbin/ipsec-kernel-policy.sh

echo 'add 192.1.2.45 192.1.2.23 esp 4523 -m transport -u 16386 -E rijndael-cbc "45-----Key----23" -A hmac-sha1 "45------Hash------23" ;' | setkey -c
echo 'add 192.1.2.23 192.1.2.45 esp 2345 -m transport -u 16385 -E rijndael-cbc "23-----Key----45" -A hmac-sha1 "23------Hash------45" ;' | setkey -c

../../guestbin/ipsec-kernel-state.sh

echo added
