grep INVALID_MAJOR_VERSION /tmp/pluto.log
grep "INVALID_MAJOR_VERSION" /tmp/pluto.log >/dev/null && echo payload found
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
