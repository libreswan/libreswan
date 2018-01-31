ipsec auto --up other
ipsec whack --trafficstatus
killall -9 pluto
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add main
ipsec auto --up main
ipsec whack --trafficstatus
echo "done"
