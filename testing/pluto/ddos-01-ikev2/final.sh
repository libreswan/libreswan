# should have gone
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

# EAST should have triggered DDOS
grep -e '^[^|].*unencrypted notification COOKIE' /tmp/pluto.log | cut -d: -f3- | head -1
