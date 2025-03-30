echo "sleeping a bit.. then deleting child"
sleep 2
ipsec whack --deletestate 2
sleep 2
ipsec _kernel policy
ipsec whack --showstates
