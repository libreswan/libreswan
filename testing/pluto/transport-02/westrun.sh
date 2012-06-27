ipsec auto --up  west--east-port3

# ping should now fail, because only tcp port 3 is allowed
ping -n -c 4 192.0.2.254

telnet east-out 3 | wc -l
telnet east-out 2 | wc -l

ipsec look
echo done
