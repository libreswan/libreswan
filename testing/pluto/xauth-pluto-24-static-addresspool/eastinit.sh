/testing/guestbin/swan-prep
echo "xnorth:xOzlFlqtwJIu2:east-any:192.0.2.101" > /etc/ipsec.d/passwd
echo "xroad:xOzlFlqtwJIu2:east-any:192.0.2.101-192.0.2.200" >> /etc/ipsec.d/passwd
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair delete-on-retransmit
ipsec auto --add east-any
echo initdone
