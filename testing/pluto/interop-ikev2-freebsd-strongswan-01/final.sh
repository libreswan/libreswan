if [ -f /var/run/pluto/pluto.pid ]; then ../../pluto/bin/ipsec-look.sh ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then ipsec statusall ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then setkey -D; setkey -DP; fi
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
