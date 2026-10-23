ipsec showstates | grep full-transcript-auth
grep 'v2AUTH transcript' /tmp/pluto.log | sort -u
grep -e 'switched' /tmp/pluto.log
grep -e 'skipping ike-sa-init-full-transcript-auth' /tmp/pluto.log
grep -e 'authentication failed' /tmp/pluto.log | sort -u
