/testing/guestbin/swan-prep
# this is enough to load the config file
ipsec pluto --debug all --stderrlog --selftest --leak-detective --config /etc/ipsec.conf > /tmp/pluto.log 2>&1
