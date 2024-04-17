# First wait for EAST's IKE_SA_INIT request to arrive.

../../guestbin/wait-for-inbound.sh 1

# EAST: process IKE_SA_INIT request; create and establish IKE SA; send
# IKE_SA_INIT response; wait for IKE_AUTH request

../../guestbin/drip-inbound.sh 1 '#1: processed IKE_SA_INIT request'
../../guestbin/wait-for-inbound.sh 2

# WEST: create IKE SA; send IKE_SA_INIT request; wait for response

ipsec up --asynchronous east-west
../../guestbin/wait-for-pluto.sh '#2: sent IKE_SA_INIT request'
../../guestbin/wait-for-inbound.sh 3

# EAST: process IKE_AUTH request; establish Child SA

../../guestbin/drip-inbound.sh 2 '#3: responder established Child SA using #1'

# WEST: process IKE_SA_INIT response; establish IKE SA; create Child
# SA; send IKE_AUTH request; wait for response

../../guestbin/drip-inbound.sh 3 '#2: processed IKE_SA_INIT response'
../../guestbin/wait-for-inbound.sh 4

# WEST: process IKE_AUTH response; establish Child SA

../../guestbin/drip-inbound.sh 4 '#4: initiator established Child SA using #2'
