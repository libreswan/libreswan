# east triggered OE, we still have our #1 which is now obsoleted
sleep 30
# state #1 should be gone by now. State #2 and #3 should be there.
ipsec showstates
# confirm it didn't create a shunt and did not nuke out policy
ipsec shuntstatus
ipsec _kernel policy
sleep 30
sleep 30
# show shuntlife= was reached - it should not have slaughtered the IPsec SA
ipsec shuntstatus
ipsec _kernel policy
