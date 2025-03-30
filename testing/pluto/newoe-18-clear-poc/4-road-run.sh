# trigger OE; packet goes out in the clear but the response on east is
# trapped (creating a shunt?).
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23

# wait on OE retransmits and rekeying?  Suspect this is waiting for
# nothing useful to happen - it is set to "clear".
sleep 5

# ping should succeed by local clear and remote pass rule
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
# no tunnel and no bare shunts expected
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec _kernel state
ipsec _kernel policy

killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done
