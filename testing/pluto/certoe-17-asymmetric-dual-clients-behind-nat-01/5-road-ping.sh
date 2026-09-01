# check traffic and shunt status
ipsec trafficstatus
ipsec shuntstatus

# trigger ping, this will be lost
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23

# wait for tunnel
../../guestbin/wait-for-pluto.sh '#1: sent IKE_SA_INIT request'
../../guestbin/wait-for-pluto.sh '#1: sent IKE_AUTH request'
../../guestbin/wait-for-pluto.sh '#1: initiator established IKE SA'
../../guestbin/wait-for-pluto.sh '#2: initiator established Child SA using #1'

#  then send ping; count changes
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec trafficstatus
