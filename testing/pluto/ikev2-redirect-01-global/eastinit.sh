/testing/guestbin/swan-prep --nokeys
../../guestbin/ip-route.sh del 192.0.1.0/24
ipsec start
../../guestbin/wait-until-pluto-started
grep "all IKE_SA_INIT requests will from now on be redirected to" /tmp/pluto.log
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec status |grep redirect
echo "initdone"
