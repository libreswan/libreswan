: ==== start ====
TESTNAME=basic-pluto-11
/testing/guestbin/swan-prep --testname $TESTNAME

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-ipv4  
## seems psk need an up on both sides AA
ipsec auto --up westnet-eastnet-ipv4 
ipsec whack --debug-control --debug-controlmore --debug-crypt
echo "initdone"
