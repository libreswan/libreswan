rm -rf OUTPUT/nss
mkdir OUTPUT/nss
ipsec initnss -d OUTPUT/nss
# generate first key
ipsec newhostkey --bits 2192 --seeddev /dev/urandom --nssdir OUTPUT/nss
# generate second key
ipsec newhostkey --bits 2192 --seeddev /dev/urandom  --nssdir OUTPUT/nss
# empty the database
rm -rf OUTPUT/nss
mkdir OUTPUT/nss
ipsec initnss -d OUTPUT/nss > /dev/null 2> /dev/null
# confirm reject too small keysizes and non-multiples of 16 for RSA
# min size is 2192 (lost to history why not 2048)
ipsec newhostkey --bits  512 --seeddev /dev/urandom --nssdir OUTPUT/nss
ipsec newhostkey --bits 1024 --seeddev /dev/urandom --nssdir OUTPUT/nss
ipsec newhostkey --bits 2048 --seeddev /dev/urandom --nssdir OUTPUT/nss
ipsec newhostkey --bits 2051 --seeddev /dev/urandom --nssdir OUTPUT/nss
ipsec newhostkey --bits 3192 --seeddev /dev/urandom --nssdir OUTPUT/nss
# there should be no keys
ipsec showhostkey --list --nssdir OUTPUT/nss
rm -rf OUTPUT/nss
