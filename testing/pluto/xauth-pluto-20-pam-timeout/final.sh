../../pluto/bin/ipsec-look.sh
grep "handling event EVENT_PAM_TIMEOUT" /tmp/pluto.log
if [ -f /etc/pam.d/pluto.stock ]; then mv /etc/pam.d/pluto.stock /etc/pam.d/pluto ; fi
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
