ipsec whack --trafficstatus
# ESP should show TFC for west and east
grep "^[^|].*: established Child SA" /tmp/pluto.log
