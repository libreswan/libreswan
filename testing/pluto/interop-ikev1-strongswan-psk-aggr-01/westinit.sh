/testing/guestbin/swan-prep --userland strongswan
# strongswan expects the certs in /etc/strongswan/certs for some reason
../../guestbin/strongswan-start.sh
echo "initdone"
