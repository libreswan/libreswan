../../pluto/bin/ipsec-look.sh
semodule -r ipsec-test-module
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
