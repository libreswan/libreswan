# confirm PPK was used
grep -e '^[^|].*PPK.*used in' /tmp/pluto.log
# confirm west sent 2 different PPK_IDENTITY_KEY notifies
grep "PPK_ID: 50 50 4b 49  44 41" /tmp/pluto.log
grep "PPK_ID: 50 50 4b 49  44 42" /tmp/pluto.log
