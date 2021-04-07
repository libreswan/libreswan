hostname | grep east > /dev/null && (grep "ADDR ADDR" /tmp/charon.log || echo "good, no double ADDR payload seen")
