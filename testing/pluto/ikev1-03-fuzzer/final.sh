# if east was already down, we crashed it
hostname |grep east > /dev/null && ipsec whack --shutdown
hostname |grep east > /dev/null && grep "packet from" /tmp/pluto.log | sed "s/^.*packet from//"
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
