../../guestbin/prep.sh

ifconfig ipsec1 create reqid 200
ifconfig ipsec1 inet tunnel 192.1.2.45 192.1.2.23
ifconfig ipsec1 inet 192.0.1.251/24 192.0.2.254

echo 'add 192.1.2.45 192.1.2.23 esp 4523 -m tunnel -u 200 -E rijndael-cbc "45--SecureKey-23";' | setkey -c
echo 'add 192.1.2.23 192.1.2.45 esp 2345 -m tunnel -u 200 -E rijndael-cbc "23--SecureKey-45";' | setkey -c

ifconfig ipsec1
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

echo added
