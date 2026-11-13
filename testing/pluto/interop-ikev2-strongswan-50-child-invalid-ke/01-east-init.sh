/testing/guestbin/swan-prep --userland strongswan
../../guestbin/ifconfig.sh eth0 add 192.0.20.254/24
../../guestbin/strongswan-start.sh
echo initdone
