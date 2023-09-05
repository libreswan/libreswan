echo "sleeping a bit.. then deleting ike"
sleep 2
ipsec whack --deletestate 1
sleep 2
../../guestbin/ipsec-kernel-policy.sh
ipsec auto --showstates
ipsec delete west-east-delete1
