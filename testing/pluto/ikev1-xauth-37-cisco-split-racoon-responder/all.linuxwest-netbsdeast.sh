# east 01-netbsdeast-init.sh

east# ../../guestbin/prep.sh
east# 
east# ../../guestbin/ifconfig.sh vioif1 add 192.0.20.254/24
east# 
east# ../../guestbin/start-racoon.sh
east# echo "initdone"

# west 02-west-init.sh

west# /testing/guestbin/swan-prep
west# ipsec auto --start
west# ../../guestbin/wait-until-pluto-started
west# ipsec auto --add west-east
west# ipsec whack --impair revival
west# echo "initdone"

# west 03-west-run.sh

west# # create a partial state on east, don't hold the hack for retransmit
west# ipsec up west-east # sanitize-retransmits
west# 
west# ipsec _kernel state
west# ipsec _kernel policy
west# 
west# ../../guestbin/ping-once.sh --up -I 192.0.2.101 192.0.2.254
west# ipsec trafficstatus
west# ../../guestbin/ping-once.sh --up -I 192.0.2.101 192.0.20.254
west# ipsec trafficstatus
west# 
west# echo done

