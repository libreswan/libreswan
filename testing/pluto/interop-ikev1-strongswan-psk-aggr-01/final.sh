# confirm the right ID types were sent/received
hostname | grep east > /dev/null &&  grep "ID type" /tmp/pluto.log | sort | uniq
