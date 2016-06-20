: ==== start ====

# use west as nexthop -- simplifies some things
route delete -net 192.0.1.0 netmask 255.255.255.0
route delete -net default
route add -net default gw 192.1.2.45

# start the local name server
named

# set up a sacrificial config
cp -a /testing/pluto/food-groups-orderly-transition-01/east-etc /tmp/etc

export IPSEC_CONFS=/tmp/etc

ipsec start ; i=0 ; while i=`expr $i + 1`; [ $i -lt 20 ] && ! { ipsec auto --status | grep 'prospective erouted' >/dev/null ; } ; do sleep 1 ; done
