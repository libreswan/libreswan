ipsec stop

# east shows what was sent across the wire; , expect two lines from
# each connection: default (missing); integ=none included; integ=none
# excluded
grep 'proposal .* chosen from:' /tmp/pluto.log

# west shows what came back, expect two lines from each connection:
# default (missing); integ=none included; integ=none excluded
grep 'proposal .* was accepted' /tmp/pluto.log

../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
