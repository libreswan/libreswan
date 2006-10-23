ipsec auto --up  west--east-port3

telnet east-out 3 | wc -l
telnet east-out 2 | wc -l

ipsec look
echo done
