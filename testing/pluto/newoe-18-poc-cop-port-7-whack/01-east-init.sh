/testing/guestbin/swan-prep --nokeys
../../guestbin/echo-server.sh -tcp -4 7 -daemon
cp east-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24  tcp  7  0"  >> /etc/ipsec.d/policies/clear-or-private
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
echo "initdone"
