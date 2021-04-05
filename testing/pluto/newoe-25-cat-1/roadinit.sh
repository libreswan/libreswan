/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
cp ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add road-east
ipsec auto --add road-west
# give OE a chance to load conns; what exactly is this waiting for?
sleep 3
ipsec auto --status
echo "initdone"
