ipsec auto --up road
ping -n -c 4 192.0.2.254
killall -9 pluto
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north
ipsec auto --up north
# annother north should be caught by uniqueids but is not yet
ipsec auto --up north
echo done
