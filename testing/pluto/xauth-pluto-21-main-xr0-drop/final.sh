grep -E '(inserting|handling) event (EVENT_v1_SEND_XAUTH|EVENT_RETRANSMIT)' OUTPUT/east.pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
