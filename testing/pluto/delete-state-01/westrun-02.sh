ipsec auto --status
echo "sleeping a bit.. 2"
ipsec whack --deletestate 1
sleep 2
ipsec auto --status
echo done
