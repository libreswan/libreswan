/testing/guestbin/swan-prep

valgrind --quiet $(ipsec -n _jambufcheck) > /dev/null || echo failed
valgrind --quiet $(ipsec -n _timecheck) > /dev/null || echo failed
valgrind --quiet $(ipsec -n _hunkcheck) > /dev/null || echo failed
valgrind --quiet $(ipsec -n _dncheck) > /dev/null || echo failed
valgrind --quiet $(ipsec -n _keyidcheck) > /dev/null || echo failed
valgrind --quiet $(ipsec -n _asn1check) > /dev/null || echo failed
valgrind --quiet $(ipsec -n _vendoridcheck) > /dev/null || echo failed
valgrind --quiet $(ipsec -n _ttodatacheck -r)

# Need to disable DNS tests; localhost is ok
valgrind --quiet $(ipsec -n _ipcheck --dns=hosts-file) > /dev/null || echo failed
