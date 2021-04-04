ipsec whack --shutdown
ip link set dev eth3 down
ip tunnel del eth3
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
