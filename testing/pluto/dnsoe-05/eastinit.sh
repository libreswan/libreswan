/testing/guestbin/swan-prep
cp east-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/clear-or-private
ip addr add 192.1.2.66/24 dev eth1
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec whack --listpubkeys
# give OE policies time to load
sleep 5
echo "initdone"
