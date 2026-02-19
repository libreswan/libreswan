/testing/guestbin/swan-prep --nokeys
rm -f /tmp/newhostkey.txt
ckaid=$(ipsec newhostkey --keytype eddsa 2>&1 | grep "showhostkey" | sed "s/^.*ckaid //")
# sanitizing brought to you by id-sanitize.sed
ipsec showhostkey --list
ipsec showhostkey --dump
ipsec showhostkey --left --ckaid "${ckaid}"
ipsec showhostkey --left --pubkey --ckaid "${ckaid}"
ipsec showhostkey --ipseckey --ckaid "${ckaid}"
ipsec showhostkey --ipseckey --pubkey --ckaid "${ckaid}"
# see description.txt for why they are different
ipsec showhostkey --pem --ckaid "${ckaid}"
ipsec showhostkey --pem --ckaid "${ckaid}" | openssl pkey -inform PEM -pubin
