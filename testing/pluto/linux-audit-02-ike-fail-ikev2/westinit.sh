/testing/guestbin/swan-prep --nokeys
setenforce 1
echo '@psk-west @psk-east: PSK "ThisIsHereToMisMatchABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"' >> /etc/ipsec.secrets
echo ': PSK "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"' >> /etc/ipsec.secrets
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-failtest
#ipsec whack --impair timeout_on_retransmit
echo "initdone"
