: dump key-length attributes to the connsole - none can be zero
grep -v '^| helper' /tmp/pluto.log | grep -A 1 'af+type: AF+IKEv2_KEY_LENGTH'
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
