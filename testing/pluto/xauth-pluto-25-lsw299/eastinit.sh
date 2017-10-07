/testing/guestbin/swan-prep
echo "use4:xOzlFlqtwJIu2:east-any" >> /etc/ipsec.d/passwd
echo "use5:xOzlFlqtwJIu2:east-any:192.0.2.100" >> /etc/ipsec.d/passwd
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add east-any
echo initdone
