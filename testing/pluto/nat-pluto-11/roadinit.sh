/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet-nonat
# should show encaps no, natt payloads none
ipsec status | grep "encaps:"
echo "initdone"
