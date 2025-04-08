# should have gone
ipsec _kernel state
ipsec _kernel policy

# EAST should have triggered DDOS
grep -e '^[^|].*unencrypted notification COOKIE' /tmp/pluto.log | cut -d: -f3- | head -1
