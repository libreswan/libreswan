ipsec auto --route road--east-pass

ipsec auto --up road--east-port3

telnet east-out 2 | wc -l
telnet east-out 3 | wc -l

echo done
