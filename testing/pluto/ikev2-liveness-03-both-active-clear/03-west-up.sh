ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# look for two probes
../../guestbin/wait-for.sh --match 'responder received message ... 2 ' -- sed -n -e 's/ [a-z]* 2 (.*/ ... 2 (...)/p' /tmp/pluto.log
../../guestbin/wait-for.sh --match 'initiator received message ... 2 ' -- sed -n -e 's/ [a-z]* 2 (.*/ ... 2 (...)/p' /tmp/pluto.log
