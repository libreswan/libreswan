ipsec whack --impair helper_thread_delay:5

# the count starts now!
ipsec whack --impair block_inbound

ipsec up --asynchronous cuckoo
../../guestbin/wait-for-pluto.sh '#3: sent CREATE_CHILD_SA request to create Child SA using IKE SA #1'

