if [ -f /tmp/iked.log ]; then cp /tmp/iked.log OUTPUT/openbsdw.iked.log ; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
