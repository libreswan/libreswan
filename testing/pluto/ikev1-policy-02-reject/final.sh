hostname | grep east > /dev/null && grep "sending notification INVALID_MAJOR_VERSION" /tmp/pluto.log
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
