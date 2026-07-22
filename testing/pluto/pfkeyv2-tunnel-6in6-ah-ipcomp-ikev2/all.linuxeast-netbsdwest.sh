east# /testing/guestbin/swan-prep --46
east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec add eastnet-westnet-ikev2
east# ipsec whack --impair suppress_retransmits
east# echo "initdone"
west# ../../guestbin/prep.sh
west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec add eastnet-westnet-ikev2
west# echo "initdone"
west# ../../guestbin/ping-once.sh --down -I 2001:db8:0:1::254 2001:db8:0:2::254
west# ipsec up eastnet-westnet-ikev2
west# ipsec _kernel policy
west# ../../guestbin/ping-once.sh --up -I 2001:db8:0:1::254 2001:db8:0:2::254
west# ipsec _kernel state
west# ../../guestbin/ping-once.sh --medium --up -I 2001:db8:0:1::254 2001:db8:0:2::254
west# ipsec _kernel state
west# dmesg | grep ipsec
