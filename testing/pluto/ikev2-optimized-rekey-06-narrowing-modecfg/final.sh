if [ -f /run/pluto/pluto.pid ]; then grep -E 'selected state microcode process CREATE_CHILD_SA' /tmp/pluto.log | sed -e 's/^| selected state microcode //' ; fi
if [ -f /run/pluto/pluto.pid ]; then ipsec whack --trafficstatus ; fi
if [ -f /run/pluto/pluto.pid ]; then ipsec _kernel policy | grep -E '^src' ; fi
