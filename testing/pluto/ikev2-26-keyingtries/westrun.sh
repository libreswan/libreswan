# this should fail
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2 #retransmits
# the state should have been deleted, but replaced via EVENT_SA_REPLACE with a new state trying
# if no STATE_s show up, this test failed
ipsec status |grep STATE_  || echo "test failed, all states went away"
# only one pending CHILD SA event should show up
ipsec status |egrep "STATE_|pending"
echo done
