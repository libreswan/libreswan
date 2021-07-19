ipsec whack --impair delete-on-retransmit
ipsec auto --route labeled
# expected to fail
echo "quit" | runcon -t netutils_t timeout 15 nc  -p 4301 -vvv 192.1.2.23 4300 2>&1 | sed "s/received in .*$/received .../"
sleep 1
echo done
