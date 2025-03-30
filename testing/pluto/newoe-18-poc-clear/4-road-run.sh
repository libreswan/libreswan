# trigger OE; check initiated
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match ": initiate on-demand" -- cat /tmp/pluto.log
ipsec _kernel state
# wait on OE retransmits and rekeying, and larval state to timeout
../../guestbin/wait-for.sh --no-match ' spi 0x00000000 ' -- ipsec _kernel state
# should show no bare shunts or tunnels
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec _kernel state
ipsec _kernel policy
# ping should succeed in the clear
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
# should show for our failed attempt at OE
grep ": initiate on-demand" /tmp/pluto.log
# save ip log
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done
