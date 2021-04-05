ipsec stop
hostname | grep east > /dev/null && grep "FIPS: Rejecting" /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
