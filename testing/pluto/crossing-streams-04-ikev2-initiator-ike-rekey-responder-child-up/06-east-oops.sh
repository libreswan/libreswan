# Wait for WEST's rekey request to arrive (and be blocked).
../../guestbin/wait-for-pluto.sh 'IMPAIR: blocking inbound message 1'
ipsec whack --no-impair block_inbound

# now get the request onto the crypto queue
ipsec whack --impair helper_thread_delay:5
date
ipsec whack --impair drip_inbound:1
date
../../guestbin/wait-for-pluto.sh '#1: IMPAIR: job 3 helper 0 #1 process_v2_CREATE_CHILD_SA_rekey_ike_request '
ipsec whack --impair helper_thread_delay:no

# With the request in limbo, initiate a new child sa exchange.  Doing
# this synchronous hangs (which is broken).
ipsec up east/0x2
