# if east was already down, the fuzzer crashed it
hostname |grep east > /dev/null && ipsec whack --shutdown
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
