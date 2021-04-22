# trigger OE
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# Wait for a rekey.  Can't sit idle as the lack of traffic will result
# in the connection being shutdown; hence the pings.
sleep 20
ping -n -q -c 4 -I 192.1.3.209 192.1.2.23
sleep 20
ping -n -q -c 4 -I 192.1.3.209 192.1.2.23
sleep 20
ping -n -q -c 4 -I 192.1.3.209 192.1.2.23
sleep 20
ping -n -q -c 4 -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match '#3' -- ipsec whack --trafficstatus
# Should show state #4 to indicate it has rekeyed
ipsec whack --trafficstatus
ipsec whack --shuntstatus
killall ip > /dev/null 2> /dev/null
echo done
