/testing/guestbin/swan-prep --userland strongswan
modprobe cast6_generic
modprobe cast5_generic
modprobe cast_common
../../pluto/bin/strongswan-start.sh
echo "initdone"
