grep -e v2N_INVALID_KE_PAYLOAD -e v2N_INVALID_SYNTAX -e SEC_ERROR /tmp/pluto.log | grep -v -e '^|'
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
