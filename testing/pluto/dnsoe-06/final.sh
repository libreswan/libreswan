# you should see one RSA and on NULL only
grep -e 'auth method: ' -e 'hash algorithm identifier' -e "^[^|].*: established IKE SA" /tmp/pluto.log
# NO ipsec tunnel should be up
ipsec whack --trafficstatus
