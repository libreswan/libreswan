test -r /run/pluto/pluto.ctl && grep -e '^[^|].*ERROR' /tmp/pluto.log
test -r /run/pluto/pluto.ctl && ipsec crlutil -L
