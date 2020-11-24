../../pluto/bin/ipsec-look.sh
ipsec whack --shutdown
semodule -r ipsec-test-module
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
