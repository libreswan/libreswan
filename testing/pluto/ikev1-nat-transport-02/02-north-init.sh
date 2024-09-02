/testing/guestbin/swan-prep --hostkeys
# confirm that the network is alive
../../guestbin/wait-until-alive 192.1.2.23
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east-7
echo done
