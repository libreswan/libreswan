grep -e 'parse IKEv2 Certificate' -e 'emit IKEv2 Certificate' -e 'ikev2 cert encoding' /tmp/pluto.log
../../guestbin/ipsec-look.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
