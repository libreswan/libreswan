/testing/guestbin/swan-prep --x509
certutil -D -n east -d sql:/etc/ipsec.d
cp road-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.23/32"  >> /etc/ipsec.d/policies/private-or-clear
# scan every 10s
ipsec pluto --config /etc/ipsec.conf --expire-shunt-interval 10
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
../../pluto/bin/wait-for.sh --match 'loaded 11,' -- ipsec auto --status
echo "initdone"
