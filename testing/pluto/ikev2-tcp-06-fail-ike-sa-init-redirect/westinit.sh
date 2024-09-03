/testing/guestbin/swan-prep --nokeys
# we can't test packet flow as we are going to redirect
../../guestbin/ip.sh route del 192.0.2.0/24
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west
echo "initdone"
