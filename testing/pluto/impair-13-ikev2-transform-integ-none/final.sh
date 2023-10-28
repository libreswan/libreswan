ipsec stop
# east shows what was sent across the wire; expect two lines for each
# of the three connections: default (missing); integ=none included;
# integ=none excluded
grep 'chosen from remote proposal' /tmp/pluto.log | sed -e 's/SPI=[0-9a-z]*/SPI=X/'
# west shows what came back, expect two lines for each of the three
# connections: default (missing); integ=none included; integ=none
# excluded
grep 'remote accepted' /tmp/pluto.log
