ipsec auto --up rekey
ipsec auto --up rekey1
ipsec auto --up rekey2
sleep 3
# do an ike rekey
ipsec whack --rekey-ike --name rekey
# do an ike rekey - but pick the conn that does not have the actual IKE SA
# is the error what we really want? Or would we want it to find the shared IKE SA? 
ipsec whack --rekey-ike --name rekey2
# rekey should not trigger IKE_SA_INIT exchanges but CREATE_CHIKD_SA exchanges
ipsec whack --rekey-child --name rekey1
ipsec whack --rekey-child --name rekey 
ipsec whack --rekey-child --name rekey2
echo done
