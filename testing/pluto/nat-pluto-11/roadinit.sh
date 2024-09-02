/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-eastnet-nonat
# should show encaps no, natt payloads none
ipsec status | grep encapsulation:
echo "initdone"
