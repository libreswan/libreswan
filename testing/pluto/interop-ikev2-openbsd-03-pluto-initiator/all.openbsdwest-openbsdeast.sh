# east 01-openbsdeast-init.sh

east# ../../guestbin/prep.sh
east# ../../guestbin/iked.sh start
east# echo "initdone"

# west 02-openbsdwest-init.sh

west# ../../guestbin/prep.sh
west# 
west# # confirm that the network is alive
west# ../../guestbin/wait-until-alive -I 192.1.2.45 192.1.2.23
west# 
west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# 
west# ipsec whack --impair suppress_retransmits
west# ipsec auto --add eastnet-westnet-ikev2
west# 
west# echo "initdone"

# west 03-openbsdwest-run.sh

west# ipsec auto --up eastnet-westnet-ikev2
west# ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
west# ipsec trafficstatus

# final final.sh

final# ipsec _kernel state
final# ipsec _kernel policy

