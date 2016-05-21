: ==== start ====

# use east as nexthop -- simplifies some things
route delete -net 192.0.2.0 netmask 255.255.255.0
route delete -net default
route add -net default gw 192.1.2.23

# start the local name server
named

ipsec start ; i=0 ; while i=`expr $i + 1`; [ $i -lt 20 ] && ! { ipsec auto --status | grep 'prospective erouted' >/dev/null ; } ; do sleep 1 ; done

ipsec auto --status
: ==== end ====
