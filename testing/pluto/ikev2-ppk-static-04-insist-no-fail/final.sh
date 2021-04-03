# east should fail PSK because it refuses PPK
grep -e '^[^|].*: authentication failed: ' /tmp/pluto.log
