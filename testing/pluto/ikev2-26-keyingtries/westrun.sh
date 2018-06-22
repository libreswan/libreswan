ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
# we should see no failures which happen when all states got deleted
sleep 10
ipsec status |grep STATE_ > /dev/null || echo "test failed, conn went away"
echo done
