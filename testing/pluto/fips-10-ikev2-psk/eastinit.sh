/testing/guestbin/swan-prep --nokeys
/testing/guestbin/fips.sh on
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
