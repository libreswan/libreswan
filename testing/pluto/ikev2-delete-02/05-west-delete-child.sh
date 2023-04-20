echo "sleeping a bit.. then deleting child"
sleep 2
ipsec whack --deletestate 2
sleep 2
../../guestbin/ipsec-kernel-policy.sh
ipsec whack --showstates
