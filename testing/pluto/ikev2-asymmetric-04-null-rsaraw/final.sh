grep -e 'auth method: ' -e 'hash algorithm identifier' -e "^[^|].* established IKE SA" OUTPUT/*pluto.log
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
