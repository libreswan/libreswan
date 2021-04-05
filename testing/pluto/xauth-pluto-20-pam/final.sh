../../guestbin/ipsec-look.sh
if [ -f /etc/pam.d/pluto.stock ]; then mv /etc/pam.d/pluto.stock /etc/pam.d/pluto ; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
