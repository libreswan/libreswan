/testing/guestbin/swan-prep
# we can't test the packetflow as we are going to redirect
../../guestbin/ip.sh route del 192.0.2.0/24
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west
echo "initdone"
