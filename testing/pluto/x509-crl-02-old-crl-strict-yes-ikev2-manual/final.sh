test -r /tmp/pluto.log && grep -e '^[^|].*ERROR' /tmp/pluto.log
test -r /tmp/pluto.log && ipsec crlutil -L
