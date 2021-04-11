ipsec whack --trafficstatus
# ESP should show TFC for west and east
grep " IPsec SA established tunnel mode" /tmp/pluto.log
