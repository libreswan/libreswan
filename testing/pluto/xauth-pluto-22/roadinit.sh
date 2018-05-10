/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
../bin/block-non-ipsec.sh
ipsec auto --add road-east
# give north time to establish first so we always get the same IP later
sleep 10
echo initdone
