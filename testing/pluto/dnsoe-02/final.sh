# A tunnel should have established with non-zero byte counters
ipsec whack --trafficstatus
grep "^[^|].*: established Child SA" /tmp/pluto.log
# you should one RSA and one NULL, asymetric OE
grep -e 'auth method: ' -e 'hash algorithm identifier' -e "^[^|].*: established IKE SA" /tmp/pluto.log
