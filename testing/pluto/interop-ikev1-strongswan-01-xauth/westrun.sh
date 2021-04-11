ipsec auto --up westnet-eastnet-ikev1
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# wait for a few DPDs
sleep 11
grep "R_U_THERE_ACK, seqno received" /tmp/pluto.log >/dev/null || echo DPD failed
# confirm --down is processed properly too
ipsec auto --down westnet-eastnet-ikev1
echo done
