ipsec whack --trafficstatus
# ESP should not show TFC
grep "^[^|].*: established Child SA" /tmp/pluto.log
