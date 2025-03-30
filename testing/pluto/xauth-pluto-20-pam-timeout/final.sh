ipsec _kernel state
ipsec _kernel policy
sed -n -e '/^[^|].*PAM: / { s/ 0.[0-9]* / 0.NNN / ; s/ 60.[0-9]* / 60.NNN / ; s/ 59.[0-9]* / 60.NNN / ; p }' /tmp/pluto.log
if [ -f /etc/pam.d/pluto.stock ]; then mv /etc/pam.d/pluto.stock /etc/pam.d/pluto ; fi
