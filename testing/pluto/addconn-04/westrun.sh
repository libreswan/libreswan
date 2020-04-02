# did pluto forked addconn pickup right config file location and load the connection
ipsec status | grep westnet-eastnet-ipv4-psk-ikev2 | grep "eroute owner"
# does status show /tmp/test.conf as config file used for startup
ipsec status | grep configfile
# rhbz#1645137 test
ipsec addconn --config /tmp/test.conf longike
ipsec whack --shutdown # stop will cause reading /etc/ipsec.conf
# rhbz#1625303 test
cp bomb.conf /etc/ipsec.conf
cp include-bomb.conf /etc/ipsec.d/
restorecon /etc/ipsec.conf /etc/ipsec.d/include-bomb.conf
# should fail properly at maxdepth recursion
ipsec addconn --verbose --config /etc/ipsec.conf --checkconfig
echo done
