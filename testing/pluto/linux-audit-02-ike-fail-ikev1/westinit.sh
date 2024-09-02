/testing/guestbin/swan-prep --hostkeys
setenforce 1
echo '@psk-west @psk-east: PSK "ThisIsHereToMisMatchABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"' >> /etc/ipsec.secrets
echo ': PSK "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"' >> /etc/ipsec.secrets
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev1-failtest
ipsec auto --add ikev1-aggr-failtest
ipsec whack --impair revival
echo "initdone"
