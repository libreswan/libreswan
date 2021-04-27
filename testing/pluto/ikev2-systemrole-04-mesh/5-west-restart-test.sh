# New files should have dropped in, and we are ready to restart
ipsec restart
../../guestbin/wait-until-pluto-started
# give OE a chance to load
../../guestbin/wait-for.sh --match 'loaded 6,' -- ipsec status
ipsec status
# trigger OE; check flow when up
../../guestbin/ping-once.sh --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus
echo done
