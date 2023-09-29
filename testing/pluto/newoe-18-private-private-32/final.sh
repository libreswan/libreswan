../../guestbin/ipsec-look.sh
# tunnel should have been established once - idleness check should prevent rekeying for OE
grep "^[^|].* established Child SA" /tmp/pluto.log
