/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair allow_null_none
ipsec auto --add esp=null-none
ipsec auto --status | grep esp=null-none
echo "initdone"
