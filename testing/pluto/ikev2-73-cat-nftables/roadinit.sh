/testing/guestbin/swan-prep --nokeys
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east
echo "initdone"
