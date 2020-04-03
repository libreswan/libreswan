rm -f /etc/ipsec.secrets
ipsec newhostkey --output /etc/ipsec.secrets --bits 2192 --seeddev /dev/urandom 2> /dev/null
# confirm permissions
ls -l /etc/ipsec.secrets | sed "s:root root .*$:root root TIMESTAMP /etc/ipsec.secrets:"
# confirm append
wc -l /etc/ipsec.secrets
ipsec newhostkey --output /etc/ipsec.secrets --bits 2192 --seeddev /dev/urandom 2> /dev/null
wc -l /etc/ipsec.secrets
rm /etc/ipsec.secrets /etc/ipsec.d/*db
ipsec initnss > /dev/null 2> /dev/null
# confirm reject too small keysizes and non-multiples of 16 for RSA
# min size is 2192 (lost to history why not 2048)
ipsec newhostkey --output /etc/ipsec.secrets --bits 512 --seeddev /dev/urandom
ipsec newhostkey --output /etc/ipsec.secrets --bits 1024 --seeddev /dev/urandom
ipsec newhostkey --output /etc/ipsec.secrets --bits 2048 --seeddev /dev/urandom
ipsec newhostkey --output /etc/ipsec.secrets --bits 2051 --seeddev /dev/urandom
ipsec newhostkey --output /etc/ipsec.secrets --bits 3192 --seeddev /dev/urandom
# there should be no keys
ipsec showhostkey --list
test -f /etc/ipsec.secrets || echo confirm no keys were created
