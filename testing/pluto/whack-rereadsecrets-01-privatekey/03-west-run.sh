# delay the helper thread by 5 seconds so that a rereadsecrets can be
# run while it is "busy"

ipsec whack --impair helper_thread_delay:5
ipsec up --asynchronous westnet-eastnet-ikev2

../../guestbin/wait-for-pluto.sh '#1: IMPAIR: job 1 helper 1 #1/#1 initiate_v2_IKE_SA_INIT_request'
ipsec rereadsecrets


../../guestbin/wait-for-pluto.sh '#1: IMPAIR: job 2 helper 1 #1/#1 process_v2_IKE_SA_INIT_response'
ipsec rereadsecrets

../../guestbin/wait-for-pluto.sh '#1: initiator established IKE SA'

../../guestbin/wait-for-pluto.sh '#1: IMPAIR: job 3 helper 1 #1/#1 submit_v2_IKE_AUTH_request_signature'
ipsec rereadsecrets

../../guestbin/wait-for-pluto.sh '#1: IMPAIR: job 4 helper 1 #1/#1 process_v2_IKE_AUTH_response'
ipsec rereadsecrets

../../guestbin/wait-for-pluto.sh '#2: initiator established Child SA using #1'
