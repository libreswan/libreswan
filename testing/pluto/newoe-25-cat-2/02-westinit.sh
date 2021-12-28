/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
cp ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 9' -- ipsec auto --status
# check no oe
ipsec whack --trafficstatus
# trigger oe; expect zero byte count on up connection
../../guestbin/ping-once.sh --down -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match 192.1.2.23 -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up   -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus
echo "initdone"
