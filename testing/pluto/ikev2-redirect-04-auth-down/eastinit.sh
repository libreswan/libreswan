/testing/guestbin/swan-prep --nokeys
../../guestbin/ip.sh route del 192.0.1.0/24
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
