echo "sleeping a bit.. then deleting ike"
sleep 2
ipsec whack --deletestate 1
sleep 2
ipsec _kernel policy
ipsec auto --showstates
ipsec delete west-east-delete1
