ipsec up westnet-eastnet-ikev2a # sanitize-retransmits
ipsec up westnet-eastnet-ikev2b # sanitize-retransmits
ipsec up westnet-eastnet-ikev2c # sanitize-retransmits
# confirm; expect: IKE #1 Child #2 #3 #4
ipsec showstates

# wait for Child SA #2 to rekey; expect: IKE #1 Child #5 #6 #7
../../guestbin/wait-for-pluto.sh --match '#5: initiator rekeyed Child SA #2'
../../guestbin/wait-for-pluto.sh --match '#2: ESP traffic information'
../../guestbin/wait-for-pluto.sh --match '#6: initiator rekeyed Child SA #3'
../../guestbin/wait-for-pluto.sh --match '#3: ESP traffic information'
../../guestbin/wait-for-pluto.sh --match '#7: initiator rekeyed Child SA #4'
../../guestbin/wait-for-pluto.sh --match '#4: ESP traffic information'
ipsec showstates

# wait for IKE SA to rekey; expect: IKE #8 Child #5 #6 #7
../../guestbin/wait-for-pluto.sh --match '#8: initiator rekeyed IKE SA #1'
../../guestbin/wait-for-pluto.sh --match '#1: deleting IKE SA'
ipsec showstates

# wait for Child SAs to rekey again; expect: IKE #8 Child #9 #10 #11
../../guestbin/wait-for-pluto.sh --match '#9: initiator rekeyed Child SA #5'
../../guestbin/wait-for-pluto.sh --match '#5: ESP traffic information'
../../guestbin/wait-for-pluto.sh --match '#10: initiator rekeyed Child SA #6'
../../guestbin/wait-for-pluto.sh --match '#6: ESP traffic information'
../../guestbin/wait-for-pluto.sh --match '#11: initiator rekeyed Child SA #7'
../../guestbin/wait-for-pluto.sh --match '#7: ESP traffic information'
ipsec showstates

echo done
