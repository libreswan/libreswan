# bring up the IKE SA
ipsec up west-cuckold

# stall the Child SA's crypto
ipsec whack --impair helper_thread_delay:5
ipsec up west-cuckoo --asynchronous
ipsec whack --impair helper_thread_delay:no

# start the delete but impair the message leaving the delete hanging
ipsec whack --impair block_outbound
ipsec whack --down-ike --name west-cuckold --asynchronous
../../guestbin/wait-for-pluto.sh '#1: IMPAIR: blocking outbound message 1'
ipsec whack --no-impair block_outbound

# wait for the child SA's stalled crypto to complete and then get
# added to the IKE SA's message queue
../../guestbin/wait-for-pluto.sh '#3: adding CREATE_CHILD_SA request'

# Now release the delete! The IKE SA and its child will die but ...
ipsec whack --impair drip_outbound:1

# The second child will revive itself using its own IKE SA
../../guestbin/wait-for-pluto.sh '#4: initiator established IKE SA'
../../guestbin/wait-for-pluto.sh '#5: initiator established Child SA using #4'

# expect second child
ipsec trafficstatus
