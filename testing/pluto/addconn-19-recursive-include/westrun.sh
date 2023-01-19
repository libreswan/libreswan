ipsec start
sleep 3
# add a connection to test adddconn as well
ipsec auto --add west
# there should be something to shutdown, proving we started properly
ipsec whack --shutdown
echo done
