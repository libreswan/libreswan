ipsec whack --trafficstatus
# These should show TFC for west and east
grep "setting TFC to" /tmp/pluto.log
grep "^[^|].* established Child SA" /tmp/pluto.log
