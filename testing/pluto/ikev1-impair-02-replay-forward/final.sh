ipsec _kernel state
ipsec _kernel policy
sed -n -e '/IMPAIR: start processing inbound replay forward/,/IMPAIR: stop processing inbound replay forward/ { /^[^|]/ p }' /tmp/pluto.log
