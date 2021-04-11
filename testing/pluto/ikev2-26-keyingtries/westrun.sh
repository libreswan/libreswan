# this should fail
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2 #retransmits

# The state should have been deleted, but replaced via event
# SA_REPLACE with a new state.  If no STATE show up, this test
# failed
../../guestbin/wait-for.sh --match 'sent IKE_AUTH request' -- ipsec status
# only one pending CHILD SA event should show up
ipsec status |egrep "STATE_|pending"
echo done
