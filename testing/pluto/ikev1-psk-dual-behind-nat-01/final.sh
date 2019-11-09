# on east this should show 2 sets of in/fwd/out policies
../../pluto/bin/ipsec-look.sh
# check both connections still work on east
hostname | grep east > /dev/null && ping -c2 192.0.2.101
hostname | grep east > /dev/null && ping -c2 192.0.2.102
ipsec whack --trafficstatus
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
