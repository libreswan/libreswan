ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
# trigger OE; traffic minus first packet should have flown through tunnel
../../guestbin/ping-once.sh --forget -I 192.1.2.23 192.1.3.209
../../guestbin/wait-for.sh --match private-or-clear -- ipsec trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.23 192.1.3.209
../../guestbin/ping-once.sh --up -I 192.1.2.23 192.1.3.209
../../guestbin/ping-once.sh --up -I 192.1.2.23 192.1.3.209
ipsec trafficstatus
