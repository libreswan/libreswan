/testing/guestbin/swan-prep --userland strongswan
# strongswan expects the certs in /etc/strongswan/certs for some reason
../../pluto/bin/strongswan-start.sh
echo "initdone"
