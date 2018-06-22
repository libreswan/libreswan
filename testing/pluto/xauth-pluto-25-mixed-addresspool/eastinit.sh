/testing/guestbin/swan-prep
ipsec start
echo "xnorth:xOzlFlqtwJIu2:east-any:192.0.2.201" > /etc/ipsec.d/passwd
echo "xroad:xOzlFlqtwJIu2:east-any" >> /etc/ipsec.d/passwd
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add east-any
echo initdone
