# this should fail, release whack socket but a state should be trying in the background
ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
sleep 10
ipsec status |grep STATE_ > /dev/null || echo "test failed, all states went away"
echo done
