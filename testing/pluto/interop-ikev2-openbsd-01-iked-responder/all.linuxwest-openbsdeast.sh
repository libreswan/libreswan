# east 01-openbsdeast-init.sh

east# ../../guestbin/prep.sh
east# ../../guestbin/iked.sh start
east# echo "initdone"

# west 02-west-init.sh

west# /testing/guestbin/swan-prep
west# # confirm that the network is alive
west# ../../guestbin/wait-until-alive -I 192.1.2.45 192.1.2.23
west# # ensure that clear text does not get through
west# iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
west# iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
west# # confirm clear text does not get through
west# ../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec auto --add westnet-eastnet-ikev2
west# ipsec auto --add westnet-eastnet-ikev2-ipv6
west# ipsec whack --impair suppress_retransmits
west# echo "initdone"

# west 03-west-run.sh

west# ipsec auto --up westnet-eastnet-ikev2
west# ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
west# ipsec trafficstatus
west# # fails
west# #ipsec auto --up  westnet-eastnet-ikev2-ipv6
west# echo done

# final final.sh

final# ipsec _kernel state
final# ipsec _kernel policy

