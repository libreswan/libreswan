if [ -f /var/run/pluto/pluto.pid ]; then ipsec _kernel state ; fi
if [ -f /var/run/pluto/pluto.pid ]; then ipsec _kernel policy ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then grep " verifying encrypted payload integrity failed" /tmp/charon.log ; fi
