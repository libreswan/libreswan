test -r /tmp/pluto/log && grep -e '^[^|].*certificate revoked' -e ERROR /tmp/pluto.log
../../guestbin/nic-ocspd.sh --log
