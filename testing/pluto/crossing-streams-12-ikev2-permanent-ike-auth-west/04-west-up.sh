# Wait for EAST IKE_SA_INIT request.
../../guestbin/wait-for-inbound.sh 1

# Process EAST IKE_SA_INIT request.
../../guestbin/drip-inbound.sh 1 '#1: sent IKE_SA_INIT response'
../../guestbin/wait-for-inbound.sh 2

# Initial connection on WEST, wait for sent IKE_SA_INIT request and EAST response.
ipsec up --asynchronous east-west
../../guestbin/wait-for-pluto.sh '#2: sent IKE_SA_INIT request'
../../guestbin/wait-for-inbound.sh 3

# Process IKE_SA_INIT response from EAST 
../../guestbin/drip-inbound.sh 3 '#2: processed IKE_SA_INIT response'

# Wait for WEST sent IKE_AUTH request 
../../guestbin/wait-for-pluto.sh '#2: sent IKE_AUTH request'
../../guestbin/wait-for-inbound.sh 4

# Process EAST IKE_AUTH request - crossing-stream!
# WEST IKE SA nonce is higher and hence send AUTHENTICATION_FAILED to EAST
../../guestbin/drip-inbound.sh 2 '#1: IKE SA #2 has outstanding IKE_AUTH request'
../../guestbin/wait-for-pluto.sh '#1: responding to IKE_AUTH message .* AUTHENTICATION_FAILED'
../../guestbin/wait-for-pluto.sh '#1: deleting IKE SA'

# Child SA established using WEST IKE SA
../../guestbin/drip-inbound.sh 4 '#3: initiator established Child SA using #2;'
