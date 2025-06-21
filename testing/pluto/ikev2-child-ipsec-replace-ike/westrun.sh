ipsec auto --up westnet-eastnet-ikev2a
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

ipsec auto --up westnet-eastnet-ikev2b
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254

ipsec auto --up westnet-eastnet-ikev2c
ipsec whack --trafficstatus

# wait for the replace
../../guestbin/wait-for-pluto.sh '#5: initiating IKEv2 connection'

../../guestbin/wait-for-pluto.sh '#6: initiator established Child SA using #5' | sed -e 's/[a-c]"/."/'
../../guestbin/wait-for-pluto.sh '#7: initiator established Child SA using #5' | sed -e 's/[a-c]"/."/'
../../guestbin/wait-for-pluto.sh '#8: initiator established Child SA using #5' | sed -e 's/[a-c]"/."/'

../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254

ipsec whack --trafficstatus |  sed -e 's/[a-c]"/."/'

echo done
