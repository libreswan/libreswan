ping -n -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 5
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# prevent delete notify
ipsec whack --impair send-no-delete
ipsec restart
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
ping -n -c 1 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# test the new tunnel works properly
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
# Now immitate a second indepdent client to east to show this 2nd client doesn't kill 1st client
killall -9 pluto
ip addr del 192.1.3.209/24 dev eth0
ip addr add 192.1.3.210/24 dev eth0
ip route add 0.0.0.0/0 via 192.1.3.254
ipsec restart
# wait on OE to load
sleep 5
ping -n -c 2 -I 192.1.3.210 192.1.2.23
sleep 1
ipsec whack --trafficstatus
echo done
