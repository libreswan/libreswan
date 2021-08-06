# A tunnel should have established with non-zero byte counters
grep "^[^|].*: established Child SA" /tmp/pluto.log
# you should RSA and NULL
grep -e 'auth method: ' -e 'hash algorithm identifier' -e "^[^|].*: established IKE SA" /tmp/pluto.log
