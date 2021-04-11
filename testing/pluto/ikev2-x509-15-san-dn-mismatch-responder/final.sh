# confirm the right ID types were sent/received
grep "ID type" /tmp/pluto.log | sort | uniq
grep "RSA authentication failed" /tmp/pluto.log
