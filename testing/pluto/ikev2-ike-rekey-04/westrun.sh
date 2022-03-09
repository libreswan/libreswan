ipsec auto --up westnet-eastnet-ikev2a
ipsec auto --up westnet-eastnet-ikev2b
ipsec auto --up westnet-eastnet-ikev2c
# confirm
ipsec showstates # expect: IKE #1 Child #2 #3 #4
# wait for Child SAs to rekey
sleep 30
ipsec showstates # expect: IKE #1 Child #5 #6 #7
# wait for IKE SA to rekey
sleep 20
ipsec showstates # expect: IKE #8 Child #9 #10 #11
# wait for Child SAs to rekey again
sleep 30
ipsec showstates # expect: IKE #8 Child #12 #13 #14
echo done
