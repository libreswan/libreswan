: ==== start ====
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-ipcomp
/testing/pluto/basic-pluto-01/eroutewait.sh trap

ipsec auto --up  westnet-eastnet-ipcomp
ipsec look
echo done
