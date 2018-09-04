/testing/guestbin/swan-prep
cp east-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.254/32"  >> /etc/ipsec.d/policies/clear-or-private
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
# give OE policies time to load
sleep 5
echo "initdone"
