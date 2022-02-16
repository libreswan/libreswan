ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# look for other end sending us probes
../../guestbin/wait-for.sh --match 'received message request 1' -- sed -n -e '/Message ID/ s/ (.*/ (...)/p' /tmp/pluto.log
