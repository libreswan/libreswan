grep -e 'auth method: ' -e 'hash algorithm identifier' -e "^[^|].* established IKE SA" OUTPUT/*pluto.log
../../guestbin/ipsec-look.sh
