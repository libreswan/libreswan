if [ -f /var/run/pluto/pluto.pid ]; then ../../guestbin/ipsec-kernel-state.sh ; fi
if [ -f /var/run/pluto/pluto.pid ]; then ../../guestbin/ipsec-kernel-policy.sh ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then strongswan status ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then grep "received DELETE for ESP CHILD_SA with SPI" /tmp/charon.log > /dev/null || echo "DELETE FAILED"; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then grep "processing failed" /tmp/charon.log; fi
