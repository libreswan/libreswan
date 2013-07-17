echo "sleeping a bit.. 20"
sleep 20
ipsec whack --deletestate 2
ipsec whack --deletestate 1
ipsec auto --status
