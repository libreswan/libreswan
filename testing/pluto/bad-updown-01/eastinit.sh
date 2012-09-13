: ==== start ====
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet
/testing/pluto/bin/eroutewait.sh trap
