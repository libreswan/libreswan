# trigger OE; then wait
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# prevent delete notify
ipsec whack --impair send_no_delete
ipsec whack --shutdown
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
# re-trigger OE
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
# test the new tunnel works properly
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23

# Now imitate a second independent client to east to show this 2nd
# client doesn't kill 1st client
ipsec whack --impair send_no_delete
ipsec whack --shutdown
../../guestbin/ip.sh address del 192.1.3.209/24 dev eth0
../../guestbin/ip.sh address add 192.1.3.210/24 dev eth0
../../guestbin/ip.sh route add 0.0.0.0/0 via 192.1.3.254
# wait on OE to load; give it a different byte count
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/ping-once.sh --forget -I 192.1.3.210 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.210 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.1.3.210 192.1.2.23
echo done
