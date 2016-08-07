/testing/guestbin/swan-prep --nokeys --fips
ipsec newhostkey
ipsec showhostkey --list
ckaid=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')
ipsec showhostkey --left --ckaid $ckaid

