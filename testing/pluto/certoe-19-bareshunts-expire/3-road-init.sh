/testing/guestbin/swan-prep --x509
ipsec certutil -D -n east
cp road-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/private
echo "192.1.4.66/32"  >> /etc/ipsec.d/policies/private-or-clear
# scan every 10s
ipsec pluto --config /etc/ipsec.conf --expire-shunt-interval 10
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 12' -- ipsec auto --status
echo "initdone"
