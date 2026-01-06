# if east was already down, we crashed it
ipsec whack --shutdown
sed -n -e 's/^.*: packet from /packet from /p' /tmp/pluto.log
