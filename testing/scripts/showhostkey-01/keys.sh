: ==== start ====
#!/bin/sh
TZ=GMT export TZ

# test argument processing and help
ipsec showhostkey
ipsec showhostkey --help

# see if we can view the raw data on each key
ipsec showhostkey --dump
ipsec showhostkey --dump --verbose

: error to load west.pem is expected
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --dump
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --dump  --verbose

ipsec showhostkey --left
ipsec showhostkey --right
ipsec showhostkey --txt 192.168.1.2
ipsec showhostkey --key
ipsec showhostkey --x509self
ipsec showhostkey --x509req
ipsec showhostkey --x509cert
ipsec showhostkey --id east --left
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --id east --left
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --id west --right
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --left
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --right
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --key
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --txt 192.168.1.3
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --x509self
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --x509req
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --x509cert

: ==== end ====
