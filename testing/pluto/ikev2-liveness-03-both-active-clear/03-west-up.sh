ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# look for a probe
../../guestbin/wait-for.sh --match 'received message ... 2:' -- sed -n -e 's/ [a-z]* 2: ike.*/ ... 2: .../p' /tmp/pluto.log
