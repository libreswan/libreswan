# east initiated sending an IKE_SA_INIT request;
# hold east's IKE_SA_INIT request as inbound message 1
../../guestbin/wait-for-inbound.sh 1

# on west, initiate creating west's IKE #1;
# hold east's IKE_SA_INIT response as inbound message 2
ipsec up --asynchronous east-west
../../guestbin/wait-for.sh --match '^".*#1: sent IKE_SA_INIT request' -- cat /tmp/pluto.log
../../guestbin/wait-for-inbound.sh 2

# on west, respond to east's IKE_SA_INIT request (message 1)
# create east's IKE SA #2;
# hold east's IKE_AUTH request as inbound message 3
ipsec whack --impair drip_inbound:1
../../guestbin/wait-for.sh --match '^".*#2: sent IKE_SA_INIT' -- cat /tmp/pluto.log
../../guestbin/wait-for-inbound.sh 3

# on west, process east's IKE_SA_INIT response (message 2);
# establish west's IKE SA #1; and create west's Child SA #3
# hold east's IKE_AUTH response as inbound message 4
ipsec whack --impair drip_inbound:2
../../guestbin/wait-for.sh --match '^".*#1: sent IKE_AUTH request'  -- cat /tmp/pluto.log
../../guestbin/wait-for-inbound.sh 4

# on west, process east's IKE_SA_AUTH response (message 4)
# establish west's Child SA #3
ipsec whack --impair drip_inbound:4
../../guestbin/wait-for.sh --match 'established Child SA using #1' -- cat /tmp/pluto.log

# on west, process east's IKE_SA_AUTH request (message 3)
# establish east's IKE SA #2 and Child SA #4
ipsec whack --impair drip_inbound:3
../../guestbin/wait-for.sh --match 'established Child SA using #2'  -- cat /tmp/pluto.log
