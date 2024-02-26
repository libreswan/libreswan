/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn

ipsec add addconn-leftid=%fromcert
ipsec add addconn-leftid=%none
ipsec add addconn-leftid=%null
ipsec add addconn-leftid=%any
ipsec add addconn-leftid=ipv4
ipsec add addconn-leftid=at-hash-hex
ipsec add addconn-leftid=at-tilda-hex
ipsec add addconn-leftid=at-lsquare-foo
ipsec add addconn-leftid=at-lsquare-foo-rsquare
ipsec add addconn-leftid=at-foo
ipsec add addconn-leftid=foo-at-bar
ipsec add addconn-leftid=foo

ipsec connectionstatus | grep ' id'
