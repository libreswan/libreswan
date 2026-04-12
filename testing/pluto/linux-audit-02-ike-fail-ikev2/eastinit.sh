/testing/guestbin/swan-prep --nokeys
setenforce 1
echo ': PSK "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"' >> /etc/ipsec.secrets
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add ikev2
echo "initdone"
