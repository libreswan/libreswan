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

ipsec enumcheck | cmp ../../enumcheck/OUTPUT.enumcheck.txt - || echo "Does the file OUTPUT.enumcheck.txt need updating?"

# other checks

ipsec fmtcheck > /dev/null || echo failed
ipsec timecheck > /dev/null || echo failed

# XXX: Don't enable for now as ipcheck tries to talk to DNS :-(

#ipsec ipcheck > /dev/null || echo failed
