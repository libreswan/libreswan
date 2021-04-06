../../guestbin/ipsec-look.sh
ipsec stop
grep -e '; already' -e 'discarding packet' /tmp/pluto.log
