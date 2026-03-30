# east 01-east-init.sh

east# /testing/guestbin/swan-prep --hostkeys
east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec auto --add westnet-eastnet-null
east# ipsec auto --status | grep westnet-eastnet-null
east# echo "initdone"

# west 02-freebsdwest-init.sh

west# ../../guestbin/prep.sh

# west 03-freebsdwest-run.sh

west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec whack --impair suppress_retransmits
west# ipsec auto --up westnet-eastnet-default
west# ipsec _kernel state | grep 'replay[-_=]'
west# ipsec stop
west# 
west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec whack --impair suppress_retransmits
west# ipsec auto --up westnet-eastnet-0
west# ipsec _kernel state | grep 'replay[-_=]'
west# ipsec stop
west# 
west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec whack --impair suppress_retransmits
west# ipsec auto --up westnet-eastnet-64
west# ipsec _kernel state | grep 'replay[-_=]'
west# ipsec stop
west# 
west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec whack --impair suppress_retransmits
west# ipsec auto --up westnet-eastnet-256
west# ipsec _kernel state | grep 'replay[-_=]'
west# ipsec stop
west# 
west# echo done

