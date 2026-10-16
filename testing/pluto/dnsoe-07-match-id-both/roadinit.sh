/testing/guestbin/swan-prep --hostkeys
cp ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private
ipsec start
../../guestbin/wait-until-pluto-started
dig +short @192.1.3.254 road.testing.libreswan.org IPSECKEY | sort
ipsec whack --listpubkeys
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 6,' -- ipsec status
echo "initdone"
