# both east and west should still have one IKE SA #1
ipsec status | grep west-east
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
