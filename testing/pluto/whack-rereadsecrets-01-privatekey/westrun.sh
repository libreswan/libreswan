# delay the helper thread by 5 seconds so that a rereadsecrets can be
# run while it is "busy"

ipsec whack --impair helper_thread_delay:5
ipsec up --asynchronous westnet-eastnet-ikev2

../../guestbin/wait-for-pluto.sh 'IMPAIR: .* #1: task 1, .* initiate_v2_IKE_SA_INIT_request'
ipsec rereadsecrets

../../guestbin/wait-for-pluto.sh 'IMPAIR: .* #1: task 2, .* process_v2_IKE_SA_INIT_response'
ipsec rereadsecrets

../../guestbin/wait-for-pluto.sh 'initiator established IKE SA'

../../guestbin/wait-for-pluto.sh 'IMPAIR: .* #1: task 3, .* submit_v2_IKE_AUTH_request_signature'
ipsec rereadsecrets

../../guestbin/wait-for-pluto.sh 'IMPAIR: .* #1: task 4, .* process_v2_IKE_AUTH_response'
ipsec rereadsecrets

../../guestbin/wait-for-pluto.sh '#2: initiator established Child SA using #1'
