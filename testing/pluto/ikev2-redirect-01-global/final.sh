../../guestbin/ipsec-look.sh
# confirm east is in unrouted state again
hostname | grep east > /dev/null && ipsec status |grep "eroute owner"
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
