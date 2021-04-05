/testing/guestbin/swan-prep
setenforce 1
echo '@psk-west-v2 @psk-east-v2: PSK "ThisIsHereToMisMatch"' >> /etc/ipsec.secrets
echo ': PSK "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"' >> /etc/ipsec.secrets
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev1
ipsec auto --add ikev1-aggr
ipsec auto --add ikev2
echo "initdone"
