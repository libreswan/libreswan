/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
cp road.ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-retransmits
ipsec auto --add road-east
ipsec auto --add road-west
ipsec auto --status
echo "initdone"
