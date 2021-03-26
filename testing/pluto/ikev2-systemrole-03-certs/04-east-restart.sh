# New files should have dropped in, and we are ready to restart
ipsec restart
/testing/pluto/bin/wait-until-pluto-started
ipsec status | grep 192.1.2
echo done
