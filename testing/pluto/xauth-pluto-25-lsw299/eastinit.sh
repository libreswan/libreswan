/testing/guestbin/swan-prep
echo "xnorth:xOzlFlqtwJIu2:east-any" > /etc/ipsec.d/passwd
echo "xroad:xOzlFlqtwJIu2:east-any:192.0.2.100" >> /etc/ipsec.d/passwd
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add east-any
ipsec whack --impair suppress-retransmits
echo initdone
