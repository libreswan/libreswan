# trigger OE; should establish
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# echo should go through passthrough, not increase traffic counter of tunnel
echo "PLAINTEXT" | nc -s 192.1.3.209 192.1.2.23 22
sleep 5
ipsec whack --trafficstatus
echo done
