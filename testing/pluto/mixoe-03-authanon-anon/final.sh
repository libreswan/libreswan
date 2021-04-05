# Authentication should be AUTH_NULL
hostname | grep nic > /dev/null || grep authenticated /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
