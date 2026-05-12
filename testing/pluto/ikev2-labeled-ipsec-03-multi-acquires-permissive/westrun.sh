ipsec up labeled # sanitize-retransmits
# expect policy but no states
ipsec _kernel state
ipsec _kernel policy

# trigger an acquire; both ends initiate Child SA
echo "quit" | runcon -t netutils_t nc -w 50 -p 4301 -vvv 192.1.2.23 4300 2>&1 | sed "s/received in .*$/received .../"
../../guestbin/wait-for-pluto.sh --match '#3: responder established Child SA'
# no shunts; two transports; two x two states
ipsec shuntstatus
ipsec showstates
ipsec _kernel state
ipsec _kernel policy

# let another on-demand label establish
echo "quit" | runcon -u system_u -r system_r -t sshd_t nc -w 50 -vvv 192.1.2.23 22 2>&1 | sed "s/received in .*$/received .../"
../../guestbin/wait-for-pluto.sh --match '#5: responder established Child SA'
# there should be no shunts
ipsec shuntstatus
ipsec showstates
ipsec _kernel state
ipsec _kernel policy

echo done
