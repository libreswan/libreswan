# this should fail, our testing cannot wait for whack to release, so use async
ipsec auto --up --asynchronous westnet-eastnet-ipv4-psk-ikev2
sleep 30
sleep 30
sleep 30
# the state should have been deleted, but replaced via EVENT_SA_REPLACE with a new state trying
# if no STATE_s show up, this test failed
ipsec status |grep STATE_  || echo "test failed, all states went away"
echo done
