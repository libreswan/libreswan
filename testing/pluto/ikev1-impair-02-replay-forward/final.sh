../../guestbin/ipsec-kernel-state.sh\n../../guestbin/ipsec-kernel-policy.sh
sed -n -e '/IMPAIR: start processing inbound replay forward/,/IMPAIR: stop processing inbound replay forward/ { /^[^|]/ p }' /tmp/pluto.log
