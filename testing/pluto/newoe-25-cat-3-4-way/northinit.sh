/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
cp ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
echo "192.1.3.209/32" >> /etc/ipsec.d/policies/private-or-clear
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-retransmits
ipsec auto --status
#these will create passthroguh shunts
ping -n -c 4 -I 192.1.3.33 192.1.2.23
ping -n -c 4 -I 192.1.3.33 192.1.2.45
echo "initdone"
