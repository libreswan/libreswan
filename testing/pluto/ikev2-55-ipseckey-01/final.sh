# east should have two public keys. including road fetched from dns
ipsec auto --listpubkeys
ipsec whack --trafficstatus
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
