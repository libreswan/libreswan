# if east was already down, the fuzzer crashed it
hostname |grep east > /dev/null && ipsec whack --shutdown
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
