ipsec up --asynchronous road-east-ikev2
# Brief window for the unbound queries to be sent but not yet returned.
sleep 1
ipsec whack --deletestate 2
# Give unbound's late replies time to arrive at the now deleted state.
sleep 10
echo done
