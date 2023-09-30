../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
sed -n -e '/IMPAIR: start processing inbound duplicate/,/IMPAIR: stop processing inbound duplicate/ { /^[^|]/ p }' /tmp/pluto.log
