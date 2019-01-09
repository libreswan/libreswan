/testing/guestbin/swan-prep

# Use CMP not DIFF.  When there's a difference, the output from diff
# mixed in with the output from comparing console.txt files looks too
# much like console.txt needs updating when it doesn't.

# To update OUTPUT.enumcheck.txt run something like:
# $ ./OBJ.linux.x86_64/testing/enumcheck/enumcheck > testing/enumcheck/OUTPUT.enumcheck.txt
# $ git diff

/usr/local/libexec/ipsec/enumcheck | cmp ../../enumcheck/OUTPUT.enumcheck.txt - || echo "Does the file OUTPUT.enumcheck.txt need updating?"
