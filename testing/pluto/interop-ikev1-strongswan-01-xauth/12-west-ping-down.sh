../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
# wait for a DPD; XXX: this is a debug line!
../../guestbin/wait-for.sh --match 'R_U_THERE_ACK, seqno received' -- cat /tmp/pluto.log | sed -e 's/received:.*/received:/'
# confirm --down is processed properly too
ipsec auto --down westnet-eastnet-ikev1
echo done
