ipsec whack --trafficstatus
ipsec showstates | sort
# there should be only one IKE_INIT exchange created on west
hostname | grep west > /dev/null && grep "sent IKE_SA_INIT request" /tmp/pluto.log
