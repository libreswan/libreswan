ping -n -c 2 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 5
# ping should succeed through tunnel
ping -n -c 1 -I 192.1.3.209 192.1.2.23
sleep 5
ipsec whack --trafficstatus
# echo should go through passthrough, not increase traffic counter of tunnel
echo "PLAINTEXT" | nc -s 192.1.3.209 192.1.2.23 22
sleep 5
ipsec whack --trafficstatus
echo done
