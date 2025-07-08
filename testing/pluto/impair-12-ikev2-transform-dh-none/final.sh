# east shows what was sent across the wire; expect two lines for each
# of the three connections: default (missing); integ=none included;
# integ=none excluded
sed -n -e '/^[^|].*chosen from remote proposal/ { s/SPI=[0-9a-z]*/SPI=X/; p }' /tmp/pluto.log

# west shows what came back, expect two lines for each of the three
# connections: default (missing); integ=none included; integ=none
# excluded
sed -n -e '/remote accepted/ { s/^| */| /; p }' /tmp/pluto.log
