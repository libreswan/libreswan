/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east-psk
# confirm loaded exclude entry
ipsec status |grep exclude
echo "initdone"
