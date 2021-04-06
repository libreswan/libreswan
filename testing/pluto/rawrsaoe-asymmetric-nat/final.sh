# A tunnel should have established with non-zero byte counters
grep "negotiated connection" /tmp/pluto.log
# you should RSA and NULL
grep -e 'auth method: ' -e 'hash algorithm identifier' -e ': authenticated using ' /tmp/pluto.log
