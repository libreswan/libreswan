/testing/guestbin/swan-prep
echo "xroad:xOzlFlqtwJIu2:east-any:192.0.2.201" >> /etc/ipsec.d/passwd
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add east-any
echo initdone
