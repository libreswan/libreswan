ipsec auto --add road1
ipsec auto --up road1
killall -9 pluto
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road2
ipsec auto --up road2
echo done
