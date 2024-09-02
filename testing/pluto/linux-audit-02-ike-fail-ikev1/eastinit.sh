/testing/guestbin/swan-prep --hostkeys
setenforce 1
echo ': PSK "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"' >> /etc/ipsec.secrets
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev1
ipsec auto --add ikev1-aggr
echo "initdone"
