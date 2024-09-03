/testing/guestbin/swan-prep --nokeys
ipsec start
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
