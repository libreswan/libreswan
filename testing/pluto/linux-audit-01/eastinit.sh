/testing/guestbin/swan-prep
setenforce 1
echo ': PSK "test"' >> /etc/ipsec.secrets
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ikev1
ipsec auto --add ikev1-aggr
ipsec auto --add ikev2
echo "initdone"
