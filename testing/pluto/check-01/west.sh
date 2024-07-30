/testing/guestbin/swan-prep

# Check the enum name tables
#
# Use CMP not DIFF.  When there's a difference, the output from diff
# mixed in with the output from comparing console.txt files looks too
# much like console.txt needs updating when it doesn't.
#
# To update OUTPUT.enumcheck.txt run something like:
# $ ./OBJ.linux.x86_64/testing/enumcheck/enumcheck > testing/enumcheck/OUTPUT.enumcheck.txt
# $ git diff

valgrind --quiet $(ipsec -n _enumcheck) > OUTPUT/enumcheck.out || echo "Enum check barfed"
cmp ../../programs/_enumcheck/OUTPUT.enumcheck.txt OUTPUT/enumcheck.out || echo "Does the file OUTPUT.enumcheck.txt need updating? See description.txt"

# other checks

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
