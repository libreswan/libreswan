: what should be looked for?
sed -n -f payloads.sed /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
