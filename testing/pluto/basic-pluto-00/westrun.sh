# diffs should be empty
/usr/local/libexec/ipsec/algparse -v | diff -u OUTPUT.algparse.txt -
/usr/local/libexec/ipsec/enumcheck | diff -u - ../../enumcheck/OUTPUT.enumcheck.txt
echo done
