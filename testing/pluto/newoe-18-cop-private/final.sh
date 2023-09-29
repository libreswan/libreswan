../../guestbin/ipsec-look.sh
# a tunnel should show up here
grep "^[^|].* established Child SA" /tmp/pluto.log
