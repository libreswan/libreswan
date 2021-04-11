hostname | grep east > /dev/null &&  grep "NO_PPK_AUTH verified" /tmp/pluto.log
ipsec whack --shutdown
