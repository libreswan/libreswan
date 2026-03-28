east# ../../guestbin/prep.sh
east# ../../guestbin/start-racoon.sh
east# echo "initdone"

west# /testing/guestbin/prep.sh
west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec add west-east
west# ipsec whack --impair revival
west# echo "initdone"

# create a partial state on east, don't hold the hack for retransmit

west# ipsec up west-east # sanitize-retransmits
west# ../../guestbin/ping-once.sh --up 192.0.2.254
west# echo done
