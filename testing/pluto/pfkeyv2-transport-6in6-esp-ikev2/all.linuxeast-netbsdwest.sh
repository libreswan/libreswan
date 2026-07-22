east# /testing/guestbin/swan-prep --46
east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec add eastnet-westnet-ikev2
east# ipsec whack --impair suppress_retransmits
west# ../../guestbin/prep.sh
west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec add eastnet-westnet-ikev2
west# echo "initdone"
west# ipsec up eastnet-westnet-ikev2
west# ipsec _kernel policy
west# ../../guestbin/ping-once.sh --up 2001:db8:1:2::23
west# ipsec _kernel state
west# ../../guestbin/ping-once.sh --medium --up 2001:db8:1:2::23
west# ipsec _kernel state
west# dmesg | grep ipsec
