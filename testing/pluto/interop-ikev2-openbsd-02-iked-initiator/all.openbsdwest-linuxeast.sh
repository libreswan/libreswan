# east 01-east-init.sh

east# /testing/guestbin/swan-prep
east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec auto --add eastnet-westnet-ikev2
east# ipsec whack --impair suppress_retransmits
east# echo "initdone"

# west 02-openbsdwest-init.sh

west# ../../guestbin/prep.sh
west# ../../guestbin/iked.sh start
west# echo "initdone"

# west 03-openbsdwest-run.sh

west# sleep 3
west# ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
west# sleep 3
west# ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

# final final.sh

final# ipsec _kernel state
final# ipsec _kernel policy

