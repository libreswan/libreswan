ipsec auto --up westnet-eastnet-ikev2a
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

ipsec auto --up westnet-eastnet-ikev2b
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254

ipsec auto --up westnet-eastnet-ikev2c
ipsec whack --trafficstatus

# wait for the replace
../../guestbin/wait-for.sh --match '#5: initiating IKEv2 connection to replace established IKE SA #1' -- cat /tmp/pluto.log

../../guestbin/wait-for.sh --match '#6: initiator established Child SA using #5' -- cat /tmp/pluto.log | sed -e 's/[a-c]"/."/'
../../guestbin/wait-for.sh --match '#7: initiator established Child SA using #5' -- cat /tmp/pluto.log | sed -e 's/[a-c]"/."/'
../../guestbin/wait-for.sh --match '#8: initiator established Child SA using #5' -- cat /tmp/pluto.log | sed -e 's/[a-c]"/."/'

../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254

ipsec whack --trafficstatus |  sed -e 's/[a-c]"/."/'

echo done
