/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive 192.1.2.23
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east-port3
echo done
