east# /testing/guestbin/swan-prep --46
east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec whack --impair suppress_retransmits
east# ipsec add eastnet-westnet-ikev2
east# echo "initdone"

west# ../../guestbin/prep.sh
west# ipsec start
west# ipsec add eastnet-westnet-ikev2
west# echo "initdone"

west# ipsec route eastnet-westnet-ikev2
west# ipsec _kernel state
west# ipsec _kernel policy

# trigger acquire
west# ../../guestbin/ping-once.sh --fire-and-forget -I 192.0.1.254 192.0.2.254
west# sleep 5 # negotiate
west# ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
