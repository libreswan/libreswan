# make this end think it is seeing retransmits
ipsec whack --impair suppress_retransmits
ipsec whack --impair duplicate_inbound
ipsec auto --up westnet-eastnet
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# check we didn't fail on retransmits from east
grep "unexpected message received in state" /tmp/pluto.log
echo done
