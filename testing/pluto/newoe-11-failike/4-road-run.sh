# trigger OE
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
# there is a shunt but it is not a bare shunt, so not visible using
# shunt status
../../guestbin/wait-for.sh --match ' spi 0x00000000 ' -- ipsec _kernel state
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --shuntstatus
# should see failureshunt oe-failing but we do not replace pass -> pass, so msg is still oe-failing
../../guestbin/wait-for.sh --match oe-failing -- ipsec whack --shuntstatus
# pings should work plaintext
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done
