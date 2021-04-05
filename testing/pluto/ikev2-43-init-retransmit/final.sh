../../guestbin/ipsec-look.sh
hostname | grep east > /dev/null && grep ikev2-responder-retransmit /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
