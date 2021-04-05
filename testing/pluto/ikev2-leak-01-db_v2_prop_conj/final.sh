grep NO_PROPOSAL_CHOSEN /tmp/pluto.log
ipsec whack --shutdown
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
