# trigger OE

../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus

# Kill some time while waiting for a rekey.  With a lifetime of 60s,
# margin of 10s, and fuzz of 100% it will happen somewhere between
# 40s-50s so 60s is safe.
#
# To stop the re-key declaring the connection idle, send a ping.
# Without this the re-key will see that there's been no traffic since
# the above <<ipsec whack --trafficstatus>> which is well beyond
# REKEY_MARGIN.
#
# (remember every time <<ipsec whack --trafficstatus>> runs and sees
# that traffic has followed it sets last-traffic time to "now").

sleep 30
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
sleep 30

../../guestbin/wait-for.sh --match '#3' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23

# Should show state #3 to indicate it has rekeyed
ipsec whack --trafficstatus
ipsec whack --shuntstatus
killall ip > /dev/null 2> /dev/null
echo done
