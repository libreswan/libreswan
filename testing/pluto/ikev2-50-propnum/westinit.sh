../../guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive 192.0.2.254 -I 192.0.1.254
ipsec start
../../pluto/bin/wait-until-pluto-started
echo "initdone"
