if [ -f /var/run/pluto/pluto.pid ]; then ../../pluto/bin/ipsec-look.sh ; fi
if [ -f /var/run/charon.pid ]; then strongswan status ; fi
if [ -f /var/run/charon.pid ]; then grep "received DELETE for ESP CHILD_SA with SPI" /tmp/charon.log > /dev/null || echo "DELETE FAILED"; fi
if [ -f /var/run/charon.pid ]; then grep "processing failed" /tmp/charon.log; fi
: ==== cut ====
if [ -f /var/run/pluto/pluto.pid ]; then ipsec auto --status ; fi
if [ -f /var/run/charon.pid ]; then strongswan statusall ; fi
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
