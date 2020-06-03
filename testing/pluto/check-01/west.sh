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

ipsec enumcheck > OUTPUT/enumcheck.out || echo "Enum check barfed"
cmp ../../check/enum/OUTPUT.enumcheck.txt OUTPUT/enumcheck.out || echo "Does the file OUTPUT.enumcheck.txt need updating? See description.txt"

# other checks

ipsec jambufcheck > /dev/null || echo failed
ipsec timecheck > /dev/null || echo failed
ipsec hunkcheck > /dev/null || echo failed
ipsec dncheck > /dev/null || echo failed

# Need to disable DNS tests
ipsec ipcheck --nodns > /dev/null || echo failed
