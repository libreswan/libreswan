/testing/guestbin/swan-prep
setenforce 1
echo '@psk-west-v2 @psk-east-v2: PSK "ThisIsHereToMisMatch"' >> /etc/ipsec.secrets
echo ': PSK "test"' >> /etc/ipsec.secrets
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ikev1
ipsec auto --add ikev1-aggr
ipsec auto --add ikev2
ipsec auto --add ikev2-failtest
ipsec auto --add ipsec-failtest
ipsec whack --impair delete-on-retransmit
echo "initdone"
