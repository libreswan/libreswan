# IKE SA #1(A), Child SA #2(A)
ipsec up westnet-eastnet-ikev2a
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

# Child SA #3(B)
ipsec up westnet-eastnet-ikev2b
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254

# wait for the replace
../../guestbin/wait-for-pluto.sh '#4: initiating IKEv2 connection'

../../guestbin/wait-for-pluto.sh '#5: initiator established Child SA using'
../../guestbin/wait-for-pluto.sh '#6: initiator established Child SA using'

../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254

ipsec whack --trafficstatus

echo done
