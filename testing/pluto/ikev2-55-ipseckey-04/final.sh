# both ends should have two public keys.The second from reverse dns
ipsec auto --listpubkeys
ipsec whack --trafficstatus
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
