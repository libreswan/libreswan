# diffs should be empty
./algparse.sh /usr/local/libexec/ipsec/algparse
/usr/local/libexec/ipsec/enumcheck | diff -u ../../enumcheck/OUTPUT.enumcheck.txt -
echo done
