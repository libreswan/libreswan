if [ -f /run/pluto/pluto.pid ]; then ipsec trafficstatus ; fi
if [ -f /run/pluto/pluto.pid ]; then ipsec _kernel policy | grep -E '^src' ; fi
