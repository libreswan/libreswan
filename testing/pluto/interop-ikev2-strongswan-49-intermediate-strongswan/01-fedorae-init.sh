/testing/guestbin/swan-prep --userland strongswan
../../guestbin/strongswan-start.sh
echo "initdone"
update-crypto-policies --set DEFAULT:TEST-PQ
