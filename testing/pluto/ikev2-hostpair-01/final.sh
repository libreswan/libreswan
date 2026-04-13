ipsec status | grep eastnet | sed "s/192.1.2.254:[0-9]* /192.1.2.254:PORT /"
# should show no hits
grep INVALID_IKE_SPI /tmp/pluto.log
grep MSG_TRUNC /tmp/pluto.log
grep "cannot route" /tmp/pluto.log
