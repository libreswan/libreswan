# There should be no established IKE SA and no established IPsec SA
ipsec whack --trafficstatus
# only on east, pluto should be attempting to connect to west because it has auto=start
ipsec showstates
# confirm the revive conn code triggered on east
test ! -r /tmp/pluto.log || egrep -e 'but must remain up per local policy' -e '^[^|].*CONNECTION_REVIVAL' /tmp/pluto.log
