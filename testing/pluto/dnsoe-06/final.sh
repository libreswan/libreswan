# you should see one RSA and on NULL only
grep -e 'auth method: ' -e 'hash algorithm identifier' -e ': authenticated using ' /tmp/pluto.log
# NO ipsec tunnel should be up
ipsec whack --trafficstatus
