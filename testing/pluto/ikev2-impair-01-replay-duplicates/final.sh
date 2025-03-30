ipsec _kernel state
ipsec _kernel policy
sed -n -e '/IMPAIR: start processing inbound duplicate/,/IMPAIR: stop processing inbound duplicate/ { /^[^|]/ p }' /tmp/pluto.log
