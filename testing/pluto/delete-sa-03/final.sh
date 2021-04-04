# both east and west should still have one IKE SA #1
ipsec status | grep west-east
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
