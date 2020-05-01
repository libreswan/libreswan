ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# sleep for a few seconds to run a few liveness cycles
sleep 20
# kill pluto; host may send ICMP unreachble. with iptables it won't
ipsec whack --impair send-no-delete
ipsec stop
# give dpdtimeout=30 time to trigger dpd, which shows up in final.sh
sleep 20
sleep 20
../../pluto/bin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
echo done
