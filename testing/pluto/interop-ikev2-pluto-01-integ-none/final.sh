ipsec stop

# east shows what was sent across the wire; expect two lines for each
# of the three connections: default (missing); integ=none included;
# integ=none excluded

grep 'proposal .* chosen from' /tmp/pluto.log | sed -e 's/SPI=[^;]*/SPI=X/'

# west shows what came back, expect two lines for each of the three
# connections: default (missing); integ=none included; integ=none
# excluded

grep 'remote accepted' /tmp/pluto.log

../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
