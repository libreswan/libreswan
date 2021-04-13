# should not match anything
grep "already in use" /tmp/pluto.log
# should only show 1 connection
ipsec whack --trafficstatus
