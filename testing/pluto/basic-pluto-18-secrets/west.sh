swan-prep
rm -f /etc/ipsec.secrets

# generate first key
ipsec newhostkey --bits 2192 --seeddev /dev/urandom
test ! -f /etc/ipsec.secrets || echo oops ipsec.secrets was created

# generate second key
ipsec newhostkey --bits 2192 --seeddev /dev/urandom
test ! -f /etc/ipsec.secrets || echo oops ipsec.secrets was created

# empty the database
rm /etc/ipsec.d/*db
ipsec initnss > /dev/null 2> /dev/null

# confirm reject too small keysizes and non-multiples of 16 for RSA
# min size is 2192 (lost to history why not 2048)
ipsec newhostkey --bits 512 --seeddev /dev/urandom
ipsec newhostkey --bits 1024 --seeddev /dev/urandom
ipsec newhostkey --bits 2048 --seeddev /dev/urandom
ipsec newhostkey --bits 2051 --seeddev /dev/urandom
ipsec newhostkey --bits 3192 --seeddev /dev/urandom
# there should be no keys
ipsec showhostkey --list
test ! -f /etc/ipsec.secrets || echo oops ipsec.secrets was created
