/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/block-non-ipsec.sh
ipsec auto --add road-east
# give north time to establish first so we always get the same IP later
sleep 10
echo initdone
