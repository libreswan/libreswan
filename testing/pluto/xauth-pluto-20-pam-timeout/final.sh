../../guestbin/ipsec-look.sh
grep "^[^|].*PAM: " /tmp/pluto.log
if [ -f /etc/pam.d/pluto.stock ]; then mv /etc/pam.d/pluto.stock /etc/pam.d/pluto ; fi
