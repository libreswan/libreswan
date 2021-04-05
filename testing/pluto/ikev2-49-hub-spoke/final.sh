hostname | grep nic > /dev/null || ipsec whack --trafficstatus
../../guestbin/ipsec-look.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
