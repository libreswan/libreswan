# These should NOT show TFC
grep "setting TFC to" /tmp/pluto.log
grep "^[^|].* established Child SA" /tmp/pluto.log
